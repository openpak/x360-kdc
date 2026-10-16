package gateway

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/kdc"
	"openpak/x360-kdc/internal/rc4hmac"
)

// Chunk kinds of the initiation (client to gateway) and reply.
const (
	chunkInitCore  = 0x5802 // 20 bytes: [4:8] client SPI, [8:16] client nonce
	chunkReplyCore = 0x5803 // 60 bytes
	chunkDH        = 0x5880 // 96 bytes LE, both directions
	chunkAPReq     = 0x5882
	chunkAPRep     = 0x5883
	chunkRecord    = 0x5887 // 0x11c..0x91c bytes, 3DES-CBC with the reply key

	dhLen      = 96
	recordBody = 0x118 // zeros: no disc read, no XeKeysExecute

	// Lifetimes in the reply core, in the units the firmware reads (x5 s).
	lifetimeA = 300
	lifetimeB = 60
)

// cksumHMAC is the authenticator / AP-REP checksum type 0x7dff as it is
// stored: the two bytes ff 7d of a DER INTEGER.
var cksumHMAC = []byte{0xff, 0x7d}

// RFC 2409 group 1 (768-bit MODP), generator 2.
var dhPrime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)

func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i, c := range b {
		r[len(b)-1-i] = c
	}
	return new(big.Int).SetBytes(r)
}

func leBytes(v *big.Int, n int) []byte {
	b := v.FillBytes(make([]byte, n))
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func chunk(kind uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, kind)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)+4))
	return append(b, data...)
}

// initiation is a parsed (not yet verified) SG initiation datagram.
type initiation struct {
	core      []byte // 0x5802, 20 bytes
	public    []byte // 0x5880, 96 bytes
	ap        []byte // 0x5882 payload, the AP-REQ
	signed    []byte // wire bytes before the 0x5882 chunk: what the HMAC covers
	clientSPI []byte
	cnonce    []byte
	chunks    []uint16
}

// parseInitiation checks the framing: four zero bytes, then LE (kind, size)
// chunks without duplicates, and the three chunks the gateway needs.
func parseInitiation(data []byte) (*initiation, error) {
	if len(data) < 4 || [4]byte(data[:4]) != [4]byte{} {
		return nil, errors.New("control framing")
	}
	wire := data[4:]
	seen := map[uint16][]byte{}
	var kinds []uint16
	apOffset := -1
	for off := 0; off < len(wire); {
		if len(wire)-off < 4 {
			return nil, errors.New("chunk bounds")
		}
		kind := binary.LittleEndian.Uint16(wire[off:])
		size := int(binary.LittleEndian.Uint16(wire[off+2:]))
		if size < 4 || off+size > len(wire) {
			return nil, errors.New("chunk bounds")
		}
		if _, dup := seen[kind]; dup {
			return nil, errors.New("duplicate chunk")
		}
		seen[kind] = wire[off+4 : off+size]
		kinds = append(kinds, kind)
		if kind == chunkAPReq {
			apOffset = off
		}
		off += size
	}
	core, public, ap := seen[chunkInitCore], seen[chunkDH], seen[chunkAPReq]
	if core == nil || public == nil || ap == nil {
		return nil, errors.New("SG initiation chunks")
	}
	if len(core) != 20 || len(public) != dhLen {
		return nil, errors.New("SG core/DH size")
	}
	if r := leInt(public); r.Cmp(big.NewInt(1)) <= 0 || r.Cmp(new(big.Int).Sub(dhPrime, big.NewInt(1))) >= 0 {
		return nil, errors.New("DH public range")
	}
	return &initiation{core: core, public: public, ap: ap, signed: wire[:apOffset],
		clientSPI: core[4:8], cnonce: core[8:16], chunks: kinds}, nil
}

// verified is what a successfully verified initiation yields.
type verified struct {
	name  string // account principal, "<digits>@xbox.com"
	key   []byte // sg/S0 ticket session key
	ctime der.TLV
	cusec der.TLV
}

// verify checks the sg/S0 ticket (ours: usage 2 under the ticket key), the
// account's provenance and stored certificate, ticket validity, the
// authenticator (usage 11, 5 minutes, no subkey) and the initiation HMAC.
func verify(in *initiation, ticketKey []byte, accounts *kdc.Store, ca *rsa.PublicKey, now time.Time) (*verified, error) {
	ap, err := kdc.AppSeqFields(in.ap, kdc.TagAPReq)
	if err != nil {
		return nil, fmt.Errorf("AP-REQ: %w", err)
	}
	if v, err := kdc.UintField(ap, 0); err != nil || v != kdc.PVNO {
		return nil, errors.New("AP-REQ version")
	}
	if v, err := kdc.UintField(ap, 1); err != nil || v != kdc.MsgAPReq {
		return nil, errors.New("AP-REQ type")
	}
	// ap-options: BIT STRING with only the mutual-authentication bit.
	if o, ok := ap[2]; !ok || o.Tag != der.TagBitString || string(o.Value) != "\x00\x20\x00\x00\x00" {
		return nil, errors.New("mutual authentication AP options")
	}
	tkt, ok := ap[3]
	if !ok {
		return nil, errors.New("AP-REQ ticket missing")
	}
	tf, err := kdc.AppSeqFields(tkt.Raw, kdc.TagTicket)
	if err != nil {
		return nil, fmt.Errorf("ticket: %w", err)
	}
	if realm, ok := tf[1]; !ok || string(realm.Value) != kdc.AccountRealm {
		return nil, fmt.Errorf("SG ticket realm %q", realmString(tf[1]))
	}
	if sn, ok := tf[2]; !ok {
		return nil, errors.New("SG ticket service missing")
	} else if n, err := kdc.Principal(sn); err != nil || len(n) != 2 || n[0] != kdc.SGService[0] || (n[1] != kdc.SGService[1] && n[1] != "S1") {
		// The KDC issues sg/S0; XAM presents the same ticket as sg/S1 for the
		// user-facing gateway session (sign-in applet), so both instances are accepted.
		return nil, fmt.Errorf("SG ticket service %v (want sg/S0 or sg/S1)", n)
	}
	enc, ok := tf[3]
	if !ok {
		return nil, errors.New("ticket enc-part missing")
	}
	cipher, err := kdc.EncryptedData(enc.Raw)
	if err != nil {
		return nil, fmt.Errorf("ticket enc-part: %w", err)
	}
	plain, err := rc4hmac.Decrypt(ticketKey, rc4hmac.UsageTicket, cipher)
	if err != nil {
		return nil, errors.New("ticket not issued by this server")
	}
	inner, err := kdc.AppSeqFields(plain, kdc.TagEncTkt)
	if err != nil {
		return nil, fmt.Errorf("EncTicketPart: %w", err)
	}
	cn, ok := inner[3]
	if !ok {
		return nil, errors.New("ticket identity")
	}
	names, err := kdc.Principal(cn)
	if err != nil || len(names) != 1 {
		return nil, errors.New("ticket identity")
	}
	acct := accounts.Get(names[0])
	if acct == nil || !acct.ConsoleSignatureVerified {
		return nil, errors.New("CA-backed identity provenance")
	}
	cert, err := acct.Cert()
	if err != nil {
		return nil, err
	}
	if err := kdc.VerifyCA(ca, cert); err != nil {
		return nil, fmt.Errorf("stored certificate: %w", err)
	}
	start, err1 := kdc.TimeField(inner, 6)
	end, err2 := kdc.TimeField(inner, 7)
	if err1 != nil || err2 != nil || now.Before(start) || now.After(end) {
		return nil, errors.New("ticket validity")
	}
	kf, ok := inner[1]
	if !ok {
		return nil, errors.New("SG session key")
	}
	key, err := kdc.KeyValue(kf)
	if err != nil {
		return nil, fmt.Errorf("SG session key: %w", err)
	}

	encAuth, ok := ap[4]
	if !ok {
		return nil, errors.New("authenticator missing")
	}
	acipher, err := kdc.EncryptedData(encAuth.Raw)
	if err != nil {
		return nil, fmt.Errorf("authenticator: %w", err)
	}
	aplain, err := rc4hmac.Decrypt(key, rc4hmacUsageAPAuth, acipher)
	if err != nil {
		return nil, errors.New("authenticator checksum")
	}
	auth, err := kdc.AppSeqFields(aplain, kdc.TagAuth)
	if err != nil {
		return nil, fmt.Errorf("authenticator: %w", err)
	}
	if v, err := kdc.UintField(auth, 0); err != nil || v != kdc.PVNO {
		return nil, errors.New("authenticator version")
	}
	if _, ok := auth[6]; ok {
		return nil, errors.New("authenticator subkey unsupported")
	}
	arealm, ok1 := auth[1]
	acn, ok2 := auth[2]
	crealm, ok3 := inner[2]
	if !ok1 || !ok2 || !ok3 || string(arealm.Value) != string(crealm.Value) {
		return nil, errors.New("authenticator identity")
	}
	if an, err := kdc.Principal(acn); err != nil || len(an) != 1 || an[0] != names[0] {
		return nil, errors.New("authenticator identity")
	}
	ctime, err := kdc.TimeField(auth, 5)
	if err != nil {
		return nil, errors.New("authenticator ctime")
	}
	if d := now.Sub(ctime); d >= kdc.Freshness || d <= -kdc.Freshness {
		return nil, errors.New("authenticator freshness")
	}
	cusec, ok := auth[4]
	if !ok || cusec.Tag != der.TagInteger {
		return nil, errors.New("authenticator cusec")
	}
	ck, ok := auth[3]
	if !ok || ck.Tag != der.TagSequence {
		return nil, errors.New("SG checksum missing")
	}
	cf, err := der.Fields(ck.Value)
	if err != nil {
		return nil, errors.New("SG checksum")
	}
	if t, ok := cf[0]; !ok || string(t.Value) != string(cksumHMAC) {
		return nil, errors.New("SG checksum type")
	}
	if v, ok := cf[1]; !ok || !hmac.Equal(v.Value, hmacSHA1(key, in.signed)) {
		return nil, errors.New("SG initiation HMAC")
	}
	return &verified{name: names[0], key: key, ctime: auth[5], cusec: cusec}, nil
}

// rc4hmacUsageAPAuth / rc4hmacUsageAPRep are the AP-REQ authenticator (11)
// and AP-REP enc-part (12) usages the security gateway uses.
const (
	rc4hmacUsageAPAuth = 11
	rc4hmacUsageAPRep  = 12
)

func hmacSHA1(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha1.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// keyMaterial is 5 x HMAC-SHA1(sessionKey, shared' || cnonce || snonce) with
// shared[0] += counter (firmware 8174a618): 100 bytes.
func keyMaterial(key, shared, cnonce, snonce []byte) []byte {
	var m []byte
	for counter := 0; counter < 5; counter++ {
		block := append([]byte{}, shared...)
		block[0] += byte(counter)
		m = append(m, hmacSHA1(key, block, cnonce, snonce)...)
	}
	return m
}

// replyParams are the server's random choices, injectable for tests.
type replyParams struct {
	private *big.Int // DH private
	snonce  []byte   // 8 bytes
	spi     []byte   // 4 bytes, first byte 0
}

// reply builds the answer datagram and returns it with the key material:
// 4 zero bytes, 0x5803 core, 0x5880 DH public, 0x5887 record, 0x5883 AP-REP.
func (in *initiation) reply(v *verified, client netip.Addr, p replyParams) (datagram, material []byte, err error) {
	shared := leBytes(new(big.Int).Exp(leInt(in.public), p.private, dhPrime), dhLen)
	public := leBytes(new(big.Int).Exp(big.NewInt(2), p.private, dhPrime), dhLen)
	material = keyMaterial(v.key, shared, in.cnonce, p.snonce)
	_, s2c := derive(material)

	core := make([]byte, 60)
	binary.LittleEndian.PutUint16(core[2:], 2) // 3DES, accepted by 81752AF8
	copy(core[4:8], in.clientSPI)
	copy(core[8:12], p.spi)
	copy(core[12:20], in.cnonce)
	copy(core[20:28], p.snonce)
	ip := client.As4()
	copy(core[28:32], ip[:])
	binary.LittleEndian.PutUint16(core[54:], lifetimeA)
	binary.LittleEndian.PutUint16(core[56:], lifetimeB)
	tail, err := cbc(s2c.k, p.snonce, core[28:60], true)
	if err != nil {
		return nil, nil, err
	}
	copy(core[28:60], tail)
	record, err := cbc(s2c.k, p.snonce, make([]byte, recordBody), true)
	if err != nil {
		return nil, nil, err
	}
	prefix := append(chunk(chunkReplyCore, core), chunk(chunkDH, public)...)
	prefix = append(prefix, chunk(chunkRecord, record)...)

	part := der.App(27, der.Seq(
		der.Ctx(0, v.ctime.Raw),
		der.Ctx(1, v.cusec.Raw),
		der.Ctx(2, der.Seq(
			der.Ctx(0, der.Encode(der.TagInteger, cksumHMAC)),
			der.Ctx(1, der.Octet(hmacSHA1(v.key, prefix))),
		)),
	))
	apRep := der.App(15, der.Seq(
		der.Ctx(0, der.Integer(kdc.PVNO)),
		der.Ctx(1, der.Integer(15)),
		der.Ctx(2, kdc.EncodeEncryptedData(rc4hmac.Encrypt(v.key, rc4hmacUsageAPRep, part))),
	))
	datagram = append(make([]byte, 4), prefix...)
	return append(datagram, chunk(chunkAPRep, apRep)...), material, nil
}

func realmString(f der.TLV) string { return string(f.Value) }

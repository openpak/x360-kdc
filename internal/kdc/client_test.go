package kdc

// A test-side Xbox 360: it builds the three requests the firmware sends and
// decodes the replies the way XAM's parser does, so the server is checked
// from the other end of the wire without any saved key material.

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

const ceText = "Xbox Version=2.00.17559.0 Title=0xFFFE07D1 TitleVersion=0\x00"

var till = time.Date(2037, 7, 20, 23, 34, 33, 0, time.UTC)

type console struct {
	key    *rsa.PrivateKey
	cert   []byte
	serial string
}

// newConsole makes an RSA-1024 console identity and a 424-byte certificate
// signed by ca with PSS SHA1 / MGF1-SHA1 / salt 10, the OpenPak dev format.
func newConsole(t *testing.T, ca *rsa.PrivateKey, id [5]byte) *console {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert := make([]byte, CertLen)
	copy(cert, []byte{0x01, 0xa8})
	copy(cert[0x02:], id[:])
	copy(cert[0x07:], "OPENPAKDEV")
	binary.BigEndian.PutUint32(cert[0x18:], 2)
	copy(cert[0x1c:], "20261016")
	binary.BigEndian.PutUint32(cert[0x24:], uint32(key.E))
	key.N.FillBytes(cert[0x28:0xa8])
	digest := sha1.Sum(cert[:0xa8])
	sig, err := rsa.SignPSS(rand.Reader, ca, crypto.SHA1, digest[:], &rsa.PSSOptions{SaltLength: caSaltLen, Hash: crypto.SHA1})
	if err != nil {
		t.Fatal(err)
	}
	copy(cert[0xa8:], sig)
	return &console{key: key, cert: cert, serial: "983404816962"}
}

func clientPrincipal(nameType uint64, parts ...string) []byte {
	var names []byte
	for _, p := range parts {
		names = append(names, der.String(p)...)
	}
	return der.Seq(der.Ctx(0, der.Integer(nameType)), der.Ctx(1, der.Encode(der.TagSequence, names)))
}

func ceBlock(key []byte, text string) []byte {
	m := hmac.New(sha1.New, key)
	m.Write([]byte(text))
	return append(m.Sum(nil), text...)
}

func encTimestamp(key []byte, at time.Time) []byte {
	plain := der.Seq(der.Ctx(0, der.Time(at)), der.Ctx(1, der.Integer(0)))
	return encEncryptedData(rc4hmac.Encrypt(key, rc4hmac.UsageTimestamp, plain))
}

func reqBody(cname []byte, realm string, sname []string, nonce uint32) []byte {
	parts := [][]byte{der.Ctx(0, zeroFlags())}
	if cname != nil {
		parts = append(parts, der.Ctx(1, cname))
	}
	parts = append(parts,
		der.Ctx(2, der.String(realm)),
		der.Ctx(3, clientPrincipal(2, sname...)),
		der.Ctx(5, der.Time(till)),
		der.Ctx(7, der.Nonce(nonce)),
		der.Ctx(8, der.Seq(der.Integer(etypeRC4))),
	)
	return der.Seq(parts...)
}

type paItem struct {
	typ   uint64
	value []byte
}

func kdcReqMsg(appTag int, msgType uint64, pa []paItem, body []byte) []byte {
	var pas []byte
	for _, p := range pa {
		pas = append(pas, encPadata(p.typ, p.value)...)
	}
	return der.App(appTag, der.Seq(
		der.Ctx(1, der.Integer(pvno)), der.Ctx(2, der.Integer(msgType)),
		der.Ctx(3, der.Encode(der.TagSequence, pas)), der.Ctx(4, body)))
}

// macsReq builds the console exchange. Returns the datagram, K and the DB block offset in it.
func (c *console) macsReq(t *testing.T, xmacs *rsa.PublicKey, nonce uint32, at time.Time) (data, secret []byte) {
	t.Helper()
	secret = rc4hmac.NewKey()
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, xmacs, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := make([]byte, 0, dbLen)
	for i := len(ct) - 1; i >= 0; i-- {
		db = append(db, ct[i])
	}
	ts8 := binary.LittleEndian.AppendUint64(nil, uint64(at.Unix()))
	db = append(db, ts8...)
	db = append(db, c.serial...)
	sk := sha1.Sum(secret)
	digest := sha1.Sum(append(append(append([]byte{}, ts8...), c.serial...), sk[:]...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA1, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	db = append(db, sig...)
	db = append(db, c.cert...)
	if len(db) != dbLen {
		t.Fatalf("DB length %d", len(db))
	}
	pa := []paItem{{PaDB, db}, {PaCE, ceBlock(rc4hmac.Derive(secret, 0), ceText)}, {PaEncTS, encTimestamp(secret, at)}}
	body := reqBody(clientPrincipal(10, "XE."+ConsoleDigits(c.cert)), MACSRealm, []string{Krbtgt, MACSRealm}, nonce)
	return kdcReqMsg(10, msgASReq, pa, body), secret
}

func xeasReq(name string, key []byte, nonce uint32, at time.Time) []byte {
	d8 := sha1.Sum(make([]byte, 168))
	pa := []paItem{{PaD8, d8[:]}, {PaCE, ceBlock(rc4hmac.Derive(key, 0), ceText)}, {PaEncTS, encTimestamp(key, at)}}
	return kdcReqMsg(10, msgASReq, pa, reqBody(clientPrincipal(10, name), AccountRealm, []string{Krbtgt, AccountRealm}, nonce))
}

// tgsReq builds the no-user sg/S0 request with the TGT and its session key.
func tgsReq(name string, ticket, session []byte, nonce uint32, at time.Time, mutate func(d6 []byte, auth *[][]byte)) []byte {
	body := reqBody(nil, AccountRealm, []string{sgService, sgInstance}, nonce)
	sum := md5.Sum(body)
	authFields := [][]byte{
		der.Ctx(0, der.Integer(pvno)), der.Ctx(1, der.String(AccountRealm)), der.Ctx(2, clientPrincipal(10, name)),
		der.Ctx(3, der.Seq(der.Ctx(0, der.Integer(cksumMD5)), der.Ctx(1, der.Octet(sum[:])))),
		der.Ctx(4, der.Integer(0)), der.Ctx(5, der.Time(at)), der.Ctx(7, der.Nonce(nonce)),
	}
	d6 := make([]byte, D6Len)
	binary.LittleEndian.PutUint16(d6, d6Version)
	if mutate != nil {
		mutate(d6, &authFields)
	}
	auth := der.App(2, der.Seq(authFields...))
	ap := der.App(14, der.Seq(der.Ctx(0, der.Integer(pvno)), der.Ctx(1, der.Integer(msgAPReq)), der.Ctx(2, zeroFlags()),
		der.Ctx(3, ticket), der.Ctx(4, encEncryptedData(rc4hmac.Encrypt(session, rc4hmac.UsageAuthenticator, auth)))))
	derived := rc4hmac.Derive(session, nonce)
	pa := []paItem{{PaAPReq, ap}, {PaCE, ceBlock(derived, ceText)}, {PaD6, encEncryptedData(rc4hmac.Encrypt(derived, rc4hmac.UsageD6, d6))}}
	return kdcReqMsg(12, msgTGSReq, pa, body)
}

// kdcRep is a decoded AS-REP/TGS-REP as the firmware sees it.
type kdcRep struct {
	fields  map[int]der.TLV
	padata  map[int][]byte
	ticket  []byte // raw Ticket
	session []byte
	part    map[int]der.TLV
}

// decodeRep decrypts the enc-part with key (usage 8) and checks what XAM's
// parser requires: etype 23 / 16-byte session key, the nonce echoed as the
// same signed 32-bit INTEGER bytes, the mandatory fields present.
func decodeRep(t *testing.T, data []byte, appTag byte, msgType uint64, key []byte, nonce uint32, partTag byte) *kdcRep {
	t.Helper()
	f, err := appSeqFields(data, appTag)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	if v, _ := uintField(f, 0); v != pvno {
		t.Fatal("reply pvno")
	}
	if v, _ := uintField(f, 1); v != msgType {
		t.Fatalf("reply msg-type %d", v)
	}
	r := &kdcRep{fields: f, padata: map[int][]byte{}}
	if pa, ok := f[2]; ok {
		items, err := der.Parse(pa.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			q, err := der.Fields(it.Value)
			if err != nil {
				t.Fatal(err)
			}
			typ, _ := uintField(q, 1)
			r.padata[int(typ)] = q[2].Value
		}
	}
	if tk, ok := f[5]; !ok || tk.Tag != tagTicket {
		t.Fatal("reply ticket")
	} else {
		r.ticket = tk.Raw
	}
	if len(r.ticket) > 1024 {
		t.Fatalf("ticket %d bytes exceeds XAM's 1024", len(r.ticket))
	}
	if len(f[3].Value) >= 24 {
		t.Fatal("crealm too long for XAM")
	}
	cipher, err := encryptedData(f[6].Raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rc4hmac.Decrypt(key, rc4hmac.UsageReply, cipher)
	if err != nil {
		t.Fatalf("enc-part: %v", err)
	}
	part, err := appSeqFields(plain, partTag)
	if err != nil {
		t.Fatalf("enc-part: %v", err)
	}
	r.part = part
	if r.session, err = keyValue(part[0]); err != nil {
		t.Fatalf("session key: %v", err)
	}
	wantNonce := der.Nonce(nonce)
	if string(part[2].Raw) != string(wantNonce) {
		t.Fatalf("nonce echo %x, want %x", part[2].Raw, wantNonce)
	}
	for _, n := range []int{1, 4, 5, 6, 7, 9, 10} {
		if _, ok := part[n]; !ok {
			t.Fatalf("enc-part field [%d] missing", n)
		}
	}
	return r
}

// decodeCB opens the MACS account record: cipher exactly 108, plaintext exactly 84, nonzero id.
func decodeCB(t *testing.T, rep *kdcRep, secret []byte, nonce uint32) []byte {
	t.Helper()
	pa, ok := rep.padata[PaCB]
	if !ok {
		t.Fatal("padata CB missing")
	}
	cipher, err := encryptedData(pa)
	if err != nil {
		t.Fatal(err)
	}
	if len(cipher) != CBCipherLen {
		t.Fatalf("CB cipher %d bytes, want %d", len(cipher), CBCipherLen)
	}
	rec, err := rc4hmac.Decrypt(rc4hmac.Derive(secret, nonce), rc4hmac.UsageCB, cipher)
	if err != nil || len(rec) != AccountLen {
		t.Fatalf("CB plaintext: %v %d", err, len(rec))
	}
	if binary.LittleEndian.Uint64(rec) == 0 {
		t.Fatal("CB account id is zero")
	}
	return rec
}

// decodeD7 opens the TGS service record: cipher exactly 208, plaintext exactly 184.
func decodeD7(t *testing.T, rep *kdcRep, derived []byte) []byte {
	t.Helper()
	pa, ok := rep.padata[PaD7]
	if !ok {
		t.Fatal("padata D7 missing")
	}
	cipher, err := encryptedData(pa)
	if err != nil {
		t.Fatal(err)
	}
	if len(cipher) != D7CipherLen {
		t.Fatalf("D7 cipher %d bytes, want %d", len(cipher), D7CipherLen)
	}
	rec, err := rc4hmac.Decrypt(derived, rc4hmac.UsageD7, cipher)
	if err != nil || len(rec) != D7Len {
		t.Fatalf("D7 plaintext: %v %d", err, len(rec))
	}
	return rec
}

// shape renders a DER tree as tags and lengths, so two replies that differ
// only in random keys, confounders and times compare equal.
func shape(b []byte) string {
	l, err := der.Parse(b)
	if err != nil {
		return "!" + err.Error()
	}
	s := ""
	for _, e := range l {
		s += string(rune('A'+int(e.Tag>>4))) + string(rune('a'+int(e.Tag&15))) + "[" + itoa(len(e.Value)) + "]"
		if e.Tag&0x20 != 0 {
			s += "{" + shape(e.Value) + "}"
		}
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// testHandler returns a Handler with fresh keys, an empty store under dir and a fixed clock.
func testHandler(t *testing.T, at time.Time) (*Handler, *rsa.PrivateKey) {
	t.Helper()
	xmacs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	tk, err := LoadTicketKey(filepath.Join(dir, "ticket.bin"))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{XMACS: xmacs, CA: &ca.PublicKey, Accounts: store, TicketKey: tk, SGAddress: mustAddr("10.0.2.2"), Now: func() time.Time { return at }}
	return h, ca
}

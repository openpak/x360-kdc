package kdc

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

// D6 (padata 0xD6 plaintext, 126 bytes, firmware 819484F8), little-endian:
//
//	0x00 2 version 6        0x02 8 kernel major/minor/build/qfe   0x0A 4 packed kernel version
//	0x0E 4 title id         0x12 4 title version                  0x16 4 title regions
//	0x1A 4 console region   0x1E 4 media id                       0x22 2 helper[7]
//	0x24 2 request-all flag 0x26 32 four LE u64 user ids          0x46 16 service bitmap
//	0x56 16 four LE u32 extended service ids                      0x66 24 reserved
const (
	D6Len        = 126
	d6Version    = 6
	d6UsersOff   = 0x26
	d6UsersLen   = 32
	sgService    = "sg"
	sgInstance   = "S0"
	authMaxDrift = Freshness
)

// handleTGS answers the initial no-user TGS-REQ for sg/S0 in realm XBOX.COM.
// Identity comes from the AP-REQ's ticket, which must be one of ours.
func (h *Handler) handleTGS(data []byte) ([]byte, *Result, error) {
	res := &Result{Kind: KindTGS}
	r, err := parseKDCReq(data, tagTGSReq, msgTGSReq)
	if err != nil {
		return nil, res, fmt.Errorf("TGS-REQ: %w", err)
	}
	res.Attrs = []any{"realm", r.realm, "sname", strings.Join(r.sname, "/"), "nonce", r.nonce, "padata", padataSummary(r)}
	if r.realm != AccountRealm || !equalStrings(r.sname, []string{sgService, sgInstance}) {
		return nil, res, errors.New("TGS: only sg/S0 served")
	}
	if !r.padataTypes(PaD6, PaCE, PaAPReq) {
		return nil, res, errors.New("TGS: padata set")
	}
	now := h.now()

	// AP-REQ: [0] pvno, [1] msg-type 14, [2] ap-options, [3] ticket, [4] authenticator.
	ap, err := appSeqFields(r.padata[PaAPReq], tagAPReq)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: AP-REQ: %w", err)
	}
	if v, err := uintField(ap, 0); err != nil || v != pvno {
		return nil, res, errors.New("TGS: AP version")
	}
	if v, err := uintField(ap, 1); err != nil || v != msgAPReq {
		return nil, res, errors.New("TGS: AP type")
	}
	tkt, ok := ap[3]
	if !ok {
		return nil, res, errors.New("TGS: AP-REQ ticket missing")
	}
	tf, err := appSeqFields(tkt.Raw, tagTicket)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: ticket: %w", err)
	}
	if sn, ok := tf[2]; !ok {
		return nil, res, errors.New("TGS: TGT sname")
	} else if names, err := principal(sn); err != nil || !equalStrings(names, []string{Krbtgt, AccountRealm}) {
		return nil, res, errors.New("TGS: TGT service")
	}
	inner, session, err := h.openTicket(tkt.Raw, now)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: %w", err)
	}
	id, err := ReadTicketIdentity(inner)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: %w", err)
	}
	names := []string{id.Principal}
	res.Attrs = append(res.Attrs, "cname", id.Principal)
	if id.Machine != id.Principal {
		res.Attrs = append(res.Attrs, "machine", id.Machine)
	}
	acct := h.Accounts.Get(id.Machine)
	if acct == nil {
		return nil, res, errors.New("TGS: unknown ticket identity")
	}
	if !acct.ConsoleSignatureVerified {
		return nil, res, errors.New("TGS: ticket account provenance")
	}
	cert, err := acct.Cert()
	if err != nil {
		return nil, res, fmt.Errorf("TGS: %w", err)
	}
	if err := VerifyCA(h.CA, cert); err != nil {
		return nil, res, fmt.Errorf("TGS: stored certificate: %w", err)
	}
	crealm, ok := inner[2]
	if !ok || string(crealm.Value) != AccountRealm {
		return nil, res, errors.New("TGS: ticket client realm")
	}

	// Authenticator: usage 7 under the TGT session key.
	encAuth, ok := ap[4]
	if !ok {
		return nil, res, errors.New("TGS: authenticator missing")
	}
	acipher, err := encryptedData(encAuth.Raw)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: authenticator: %w", err)
	}
	aplain, err := rc4hmac.Decrypt(session, rc4hmac.UsageAuthenticator, acipher)
	if err != nil {
		return nil, res, errors.New("TGS: authenticator checksum")
	}
	auth, err := appSeqFields(aplain, tagAuth)
	if err != nil {
		return nil, res, fmt.Errorf("TGS: authenticator: %w", err)
	}
	if arealm, ok := auth[1]; !ok || string(arealm.Value) != string(crealm.Value) {
		return nil, res, errors.New("TGS: authenticator identity")
	}
	if acn, ok := auth[2]; !ok {
		return nil, res, errors.New("TGS: authenticator identity")
	} else if an, err := principal(acn); err != nil || len(an) != 1 || !contains(id.Names(), an[0]) {
		return nil, res, errors.New("TGS: authenticator identity")
	}
	if _, ok := auth[6]; ok {
		return nil, res, errors.New("TGS: authenticator subkey path not implemented")
	}
	ctime, err := timeField(auth, 5)
	if err != nil {
		return nil, res, errors.New("TGS: authenticator ctime")
	}
	if d := now.Sub(ctime); d >= authMaxDrift || d <= -authMaxDrift {
		return nil, res, errors.New("TGS: authenticator freshness")
	}
	ck, ok := auth[3]
	if !ok || ck.Tag != der.TagSequence {
		return nil, res, errors.New("TGS: body checksum missing")
	}
	cf, err := der.Fields(ck.Value)
	if err != nil {
		return nil, res, errors.New("TGS: body checksum")
	}
	if t, err := uintField(cf, 0); err != nil || t != cksumMD5 {
		return nil, res, errors.New("TGS: body checksum type")
	}
	bodyMD5 := md5.Sum(r.bodyRaw)
	if cv, ok := cf[1]; !ok || !hmac.Equal(cv.Value, bodyMD5[:]) {
		return nil, res, errors.New("TGS: request body checksum")
	}

	// CE and D6 under D(session, nonce).
	derived := rc4hmac.Derive(session, r.nonce)
	title, err := verifyCE(derived, r.padata[PaCE])
	if err != nil {
		return nil, res, fmt.Errorf("TGS: %w", err)
	}
	d6cipher, err := encryptedData(r.padata[PaD6])
	if err != nil {
		return nil, res, fmt.Errorf("TGS: D6: %w", err)
	}
	d6, err := rc4hmac.Decrypt(derived, rc4hmac.UsageD6, d6cipher)
	if err != nil {
		return nil, res, errors.New("TGS: D6 checksum")
	}
	if len(d6) != D6Len || binary.LittleEndian.Uint16(d6) != d6Version {
		return nil, res, errors.New("TGS: D6 version/length")
	}
	var xuids []string
	for i := 0; i < d6UsersLen; i += 8 {
		if x := binary.LittleEndian.Uint64(d6[d6UsersOff+i:]); x != 0 {
			xuids = append(xuids, fmt.Sprintf("%016x", x))
		}
	}
	if len(xuids) > 0 {
		// Every user id must have been authorised by a user AS exchange
		// (user.go) along this ticket's chain.
		res.Attrs = append(res.Attrs, "user_xuids", strings.Join(xuids, ","))
		for i := 0; i < d6UsersLen; i += 8 {
			if x := binary.LittleEndian.Uint64(d6[d6UsersOff+i:]); x != 0 && !id.HasUser(x) {
				return nil, res, fmt.Errorf("TGS: user %016x was not authorised by a user AS exchange", x)
			}
		}
	}
	res.Attrs = append(res.Attrs, "title", title, "sg", h.SGAddress.String(),
		"title_id", fmt.Sprintf("%08X", binary.LittleEndian.Uint32(d6[0x0e:])),
		"kernel_version", binary.LittleEndian.Uint32(d6[0x0a:]),
		"d6", hex.EncodeToString(d6))

	// Reply: D7 under D(session, nonce) usage 1202, a fresh sg/S0 ticket and
	// EncTGSRepPart under the TGT session key, usage 8.
	sessionOut := rc4hmac.NewKey()
	d7 := encPadata(PaD7, encEncryptedData(rc4hmac.Encrypt(derived, rc4hmac.UsageD7, d7Record(h.SGAddress))))
	var ad []byte
	if len(id.Users) > 0 || id.Machine != id.Principal {
		ad = encAuthData(id.Machine, id.Users)
	}
	ticket := h.ticket(r.realm, names, r.sname, sessionOut, now, ad)
	part := encKDCRepPart(26, sessionOut, r.nonce, r.realm, r.sname, now)
	rep := encKDCRep(13, msgTGSRep, d7, r.realm, names, ticket, rc4hmac.Encrypt(session, rc4hmac.UsageReply, part))
	return rep, res, nil
}

func timeField(f map[int]der.TLV, n int) (time.Time, error) {
	v, ok := f[n]
	if !ok || v.Tag != der.TagGeneralizedTime {
		return time.Time{}, fmt.Errorf("field [%d] is not a GeneralizedTime", n)
	}
	return der.ParseTime(v.Value)
}

// keyValue reads EncryptionKey { [0] etype 23, [1] keyvalue[16] }.
func keyValue(v der.TLV) ([]byte, error) {
	if v.Tag != der.TagSequence {
		return nil, errors.New("not a sequence")
	}
	f, err := der.Fields(v.Value)
	if err != nil {
		return nil, err
	}
	if et, err := uintField(f, 0); err != nil || et != etypeRC4 {
		return nil, errors.New("etype")
	}
	k, ok := f[1]
	if !ok || k.Tag != der.TagOctetString || len(k.Value) != rc4hmac.KeyLen {
		return nil, errors.New("size")
	}
	return k.Value, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

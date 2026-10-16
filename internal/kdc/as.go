package kdc

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"openpak/x360-kdc/internal/accountcore"
	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

// Padata 0xDB (MACS console block), 828 bytes, built by XAM at 81946C70:
//
//	0x000 256 little-endian RSA-2048 OAEP ciphertext (SHA1, MGF1-SHA1, no label) -> 16-byte secret K
//	0x100   8 raw client timestamp
//	0x108  12 ASCII console serial
//	0x114 128 console RSA signature of SHA1(timestamp || serial || SHA1(K)), PKCS#1 v1.5 SHA1
//	0x194 424 console certificate (cert.go)
const (
	dbLen        = 828
	dbOAEPLen    = 256
	dbTimeOff    = 0x100
	dbSerialOff  = 0x108
	dbSigOff     = 0x114
	dbCertOff    = 0x194
	ceMACLen     = sha1.Size
	d8Len        = 20
	minSecretLen = rc4hmac.KeyLen
)

// handleAS routes an AS-REQ by realm: MACS.XBOX.COM is the console exchange,
// XBOX.COM the account exchange; anything else is recorded only.
func (h *Handler) handleAS(data []byte) ([]byte, *Result, error) {
	r, err := parseKDCReq(data, tagASReq, msgASReq)
	if err != nil {
		return nil, &Result{Kind: KindRecordOnly}, fmt.Errorf("AS-REQ: %w", err)
	}
	cn, ok := r.body[1]
	if !ok {
		return nil, &Result{Kind: KindRecordOnly}, errors.New("AS-REQ: cname missing")
	}
	cname, err := principal(cn)
	if err != nil {
		return nil, &Result{Kind: KindRecordOnly}, fmt.Errorf("AS-REQ: cname: %w", err)
	}
	if !equalStrings(r.sname, []string{Krbtgt, r.realm}) {
		return nil, &Result{Kind: KindRecordOnly}, errors.New("AS-REQ: unexpected AS service")
	}
	base := []any{"realm", r.realm, "cname", strings.Join(cname, "/"), "nonce", r.nonce, "padata", padataSummary(r)}
	switch r.realm {
	case MACSRealm:
		rep, attrs, err := h.macs(r, cname)
		return rep, &Result{Kind: KindMACS, Attrs: append(base, attrs...)}, err
	case AccountRealm:
		rep, attrs, err := h.xeas(r, cname)
		return rep, &Result{Kind: KindXEAS, Attrs: append(base, attrs...)}, err
	}
	return nil, &Result{Kind: KindRecordOnly, Attrs: base}, nil
}

func padataSummary(r *kdcReq) string {
	var parts []string
	for t, v := range r.padata {
		parts = append(parts, fmt.Sprintf("%d:%d", t, len(v)))
	}
	return strings.Join(parts, ",")
}

// macsRequest is what a fully verified MACS request establishes.
type macsRequest struct {
	secret    []byte // K, the OAEP plaintext; encrypts the AS-REP
	cert      []byte
	title     string // CE text without its NUL
	serial    string
	timestamp time.Time // PA-ENC-TIMESTAMP, decrypted (logged, not bounded: the oracle does not bound it)
}

// verifyMACS performs the console checks in the oracle's order: OAEP decrypt,
// certificate header, CA signature, console signature over the timestamp,
// serial and SHA1(K), console ID against cname, CE HMAC under D(K,0), and the
// encrypted timestamp's checksum under usage 1.
func verifyMACS(priv *rsa.PrivateKey, ca *rsa.PublicKey, r *kdcReq, cname []string) (*macsRequest, error) {
	db, ok := r.padata[PaDB]
	if !ok || len(db) != dbLen {
		return nil, errors.New("padata DB missing or not 828 bytes")
	}
	ct := make([]byte, dbOAEPLen)
	for i := range ct {
		ct[i] = db[dbOAEPLen-1-i]
	}
	secret, err := rsa.DecryptOAEP(sha1.New(), nil, priv, ct, nil)
	if err != nil {
		return nil, errors.New("OAEP block")
	}
	if len(secret) != minSecretLen {
		return nil, errors.New("client secret is not 16 bytes")
	}
	cert := db[dbCertOff:]
	if err := VerifyCA(ca, cert); err != nil {
		return nil, err
	}
	pub, err := consolePublicKey(cert)
	if err != nil {
		return nil, err
	}
	sk := sha1.Sum(secret)
	digest := sha1.Sum(append(append([]byte{}, db[dbTimeOff:dbSigOff]...), sk[:]...))
	if err := rsa.VerifyPKCS1v15(pub, 0, digestInfoSHA1(digest[:]), db[dbSigOff:dbCertOff]); err != nil {
		return nil, errors.New("console signature")
	}
	if want := []string{"XE." + ConsoleDigits(cert)}; !equalStrings(cname, want) {
		return nil, errors.New("console id/cname mismatch")
	}
	title, err := verifyCE(rc4hmac.Derive(secret, 0), r.padata[PaCE])
	if err != nil {
		return nil, err
	}
	ts, err := decryptTimestamp(secret, r.padata[PaEncTS])
	if err != nil {
		return nil, err
	}
	return &macsRequest{
		secret:    secret,
		cert:      cert,
		title:     title,
		serial:    string(db[dbSerialOff:dbSigOff]),
		timestamp: ts,
	}, nil
}

// digestInfoSHA1 wraps a SHA1 digest in the PKCS#1 DigestInfo the console
// signs (3021300906052b0e03021a05000414 || digest). VerifyPKCS1v15 with hash 0
// then compares the whole encoded message, which is exactly the oracle's
// Prehashed(SHA1) check.
func digestInfoSHA1(d []byte) []byte {
	prefix := []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
	return append(prefix, d...)
}

// verifyCE checks padata 0xCE: HMAC-SHA1[20] || NUL-terminated text, the MAC
// covering the text including its NUL. Returns the text without the NUL.
func verifyCE(key, ce []byte) (string, error) {
	if len(ce) < ceMACLen+1 {
		return "", errors.New("padata CE missing or short")
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(ce[ceMACLen:])
	if !hmac.Equal(mac.Sum(nil), ce[:ceMACLen]) {
		return "", errors.New("CE checksum")
	}
	return strings.TrimRight(string(ce[ceMACLen:]), "\x00"), nil
}

// decryptTimestamp opens padata 2 (EncryptedData etype 23, usage 1) and
// returns the PA-ENC-TS-ENC patimestamp.
func decryptTimestamp(key, pa []byte) (time.Time, error) {
	if pa == nil {
		return time.Time{}, errors.New("padata 2 missing")
	}
	cipher, err := encryptedData(pa)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	plain, err := rc4hmac.Decrypt(key, rc4hmac.UsageTimestamp, cipher)
	if err != nil {
		return time.Time{}, errors.New("timestamp checksum")
	}
	seq, err := der.One(plain)
	if err != nil || seq.Tag != der.TagSequence {
		return time.Time{}, errors.New("timestamp plaintext")
	}
	f, err := der.Fields(seq.Value)
	if err != nil {
		return time.Time{}, errors.New("timestamp plaintext")
	}
	gt, ok := f[0]
	if !ok || gt.Tag != der.TagGeneralizedTime {
		return time.Time{}, errors.New("timestamp field")
	}
	return der.ParseTime(gt.Value)
}

// macs answers the console exchange: verify, provision or reuse the machine
// account, reply with an opaque ticket, the account record in padata 0xCB
// (D(K,nonce), usage 1203) and the enc-part under K (usage 8).
func (h *Handler) macs(r *kdcReq, cname []string) ([]byte, []any, error) {
	m, err := verifyMACS(h.XMACS, h.CA, r, cname)
	if err != nil {
		return nil, nil, fmt.Errorf("MACS: %w", err)
	}
	now := h.now()
	var enrol *accountcore.Enrolment
	if h.Core != nil {
		// Fail closed on a core error or a revoked pairing. A console the core has
		// never seen is accepted as unowned.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		enrol, err = h.Core.Enrol(ctx, ConsoleDigits(m.cert))
		cancel()
		if err != nil {
			return nil, nil, fmt.Errorf("MACS: account core: %w", err)
		}
	}
	acct, issued, err := h.Accounts.Provision(m.cert, now)
	if err != nil {
		return nil, nil, fmt.Errorf("MACS: %w", err)
	}
	var coreAttrs []any
	if enrol != nil && !enrol.Owned() {
		// The core has no link: an unowned console. It still gets its machine
		// account; ownership is claimed when a person signs in on it.
		coreAttrs = []any{"core_link", "none", "console", "unowned"}
	}
	if enrol != nil && enrol.Owned() {
		if err := h.Accounts.BindCore(ConsoleDigits(m.cert)+"@"+AccountDomain, enrol.LinkID, enrol.AccountID); err != nil {
			return nil, nil, fmt.Errorf("MACS: %w", err)
		}
		coreAttrs = []any{"core_link", enrol.LinkID, "core_account", enrol.AccountID}
	}
	record, err := hex.DecodeString(acct.Record)
	if err != nil || len(record) != AccountLen {
		return nil, nil, errors.New("MACS: stored account record")
	}
	session := rc4hmac.NewKey()
	service := []string{Krbtgt, r.realm}
	cb := encPadata(PaCB, encEncryptedData(rc4hmac.Encrypt(rc4hmac.Derive(m.secret, r.nonce), rc4hmac.UsageCB, record)))
	part := encKDCRepPart(25, session, r.nonce, r.realm, service, now)
	rep := encKDCRep(11, msgASRep, cb, r.realm, cname, opaqueTicket(r.realm, service), rc4hmac.Encrypt(m.secret, rc4hmac.UsageReply, part))
	attrs := []any{"title", m.title, "console_id", hex.EncodeToString(m.cert[certIDOff : certIDOff+5]), "serial", m.serial,
		"client_time", m.timestamp.UTC().Format(time.RFC3339), "account_issued", issued}
	return rep, append(attrs, coreAttrs...), nil
}

// xeas answers the account exchange: the account must exist with verified
// provenance, its certificate must still verify against the CA, the CE HMAC
// must verify under D(accountKey,0), and the encrypted timestamp (usage 1)
// must be within Freshness. D8 is logged as a measurement, never trusted.
func (h *Handler) xeas(r *kdcReq, cname []string) ([]byte, []any, error) {
	if len(cname) != 1 {
		return nil, nil, errors.New("XEAS: principal count")
	}
	acct := h.Accounts.Get(cname[0])
	if acct == nil {
		return nil, nil, errors.New("XEAS: unknown account: CA-backed MACS provisioning required")
	}
	if !acct.ConsoleSignatureVerified {
		return nil, nil, errors.New("XEAS: unverified account provenance")
	}
	cert, err := acct.Cert()
	if err != nil {
		return nil, nil, fmt.Errorf("XEAS: %w", err)
	}
	if err := VerifyCA(h.CA, cert); err != nil {
		return nil, nil, fmt.Errorf("XEAS: stored certificate: %w", err)
	}
	key, err := acct.Key()
	if err != nil {
		return nil, nil, fmt.Errorf("XEAS: %w", err)
	}
	if !r.padataTypes(PaD8, PaCE, PaEncTS) {
		return nil, nil, errors.New("XEAS: unexpected padata set")
	}
	if len(r.padata[PaD8]) != d8Len {
		return nil, nil, errors.New("XEAS: D8 length")
	}
	title, err := verifyCE(rc4hmac.Derive(key, 0), r.padata[PaCE])
	if err != nil {
		return nil, nil, fmt.Errorf("XEAS: %w", err)
	}
	ts, err := decryptTimestamp(key, r.padata[PaEncTS])
	if err != nil {
		return nil, nil, fmt.Errorf("XEAS: %w", err)
	}
	now := h.now()
	if d := now.Sub(ts); d >= Freshness || d <= -Freshness {
		return nil, nil, errors.New("XEAS: timestamp outside 5 minutes")
	}
	session := rc4hmac.NewKey()
	service := []string{Krbtgt, r.realm}
	ticket := h.authTicket(r.realm, cname, service, session, now)
	part := encKDCRepPart(25, session, r.nonce, r.realm, service, now)
	rep := encKDCRep(11, msgASRep, nil, r.realm, cname, ticket, rc4hmac.Encrypt(key, rc4hmac.UsageReply, part))
	attrs := []any{"title", title, "kernel_block_sha1", hex.EncodeToString(r.padata[PaD8]), "client_time", ts.UTC().Format(time.RFC3339)}
	return rep, attrs, nil
}

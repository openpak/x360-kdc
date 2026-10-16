package kdc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

var t0 = time.Date(2026, 10, 16, 15, 6, 0, 0, time.UTC)

// handle runs the handler and fails the test on rejection.
func handle(t *testing.T, h *Handler, data []byte) ([]byte, *Result) {
	t.Helper()
	rep, res, err := h.Handle(data)
	if err != nil {
		t.Fatalf("rejected: %v (%v)", err, res.Attrs)
	}
	if rep == nil {
		t.Fatalf("no reply: %v", res)
	}
	return rep, res
}

// reject runs the handler and requires a rejection whose message contains want.
func reject(t *testing.T, h *Handler, data []byte, want string) {
	t.Helper()
	rep, _, err := h.Handle(data)
	if err == nil {
		t.Fatalf("accepted, wanted rejection %q (reply %d bytes)", want, len(rep))
	}
	if rep != nil {
		t.Fatalf("rejection %v produced a reply", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("rejection %q, want %q", err, want)
	}
}

// flip returns a copy of data with one bit changed at the first occurrence of needle plus off.
func flip(t *testing.T, data, needle []byte, off int) []byte {
	t.Helper()
	i := bytes.Index(data, needle)
	if i < 0 {
		t.Fatal("needle not found")
	}
	out := append([]byte{}, data...)
	out[i+off] ^= 1
	return out
}

// TestFullExchange is the whole sign-in as the firmware performs it: MACS,
// then XEAS with the issued account key, then TGS with the issued TGT.
func TestFullExchange(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{0x6f, 0x74, 0xc8, 0x86, 0x36})
	if got := ConsoleDigits(c.cert); got != "478700668470" {
		t.Fatalf("console digits %s", got)
	}

	// MACS.
	nonce := uint32(0x879f0666)
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, nonce, t0)
	rep, res := handle(t, h, req)
	if res.Kind != KindMACS {
		t.Fatal(res.Kind)
	}
	as := decodeRep(t, rep, tagASRep, msgASRep, secret, nonce, tagEncAS)
	cb := decodeCB(t, as, secret, nonce)
	wantID := uint64(0x0009000000000000) | ConsoleID(c.cert)
	if binary.LittleEndian.Uint64(cb) != wantID {
		t.Fatalf("account id %#x", binary.LittleEndian.Uint64(cb))
	}
	name := strings.TrimRight(string(cb[8:24]), "\x00") + "@" + strings.TrimRight(string(cb[24:44]), "\x00")
	if name != "478700668470@xbox.com" || strings.TrimRight(string(cb[44:68]), "\x00") != "XBOX.COM" {
		t.Fatalf("account strings %q %q", name, cb[44:68])
	}
	acctKey := cb[68:84]
	stored := h.Accounts.Get(name)
	if stored == nil || !stored.ConsoleSignatureVerified {
		t.Fatal("account not stored with provenance")
	}
	if k, _ := stored.Key(); !bytes.Equal(k, acctKey) {
		t.Fatal("stored key differs from CB key")
	}
	if len(rep) != 545 {
		t.Errorf("MACS reply %d bytes, the live reply was 545", len(rep))
	}

	// A second MACS from the same console reuses the account: same CB record.
	req2, secret2 := c.macsReq(t, &h.XMACS.PublicKey, nonce+1, t0)
	rep2, _ := handle(t, h, req2)
	cb2 := decodeCB(t, decodeRep(t, rep2, tagASRep, msgASRep, secret2, nonce+1, tagEncAS), secret2, nonce+1)
	if !bytes.Equal(cb, cb2) {
		t.Fatal("account record changed between MACS exchanges")
	}
	if shape(rep) != shape(rep2) {
		t.Fatal("MACS reply shape differs between runs")
	}

	// XEAS.
	xn := uint32(0xb3ef5bf0)
	xrep, xres := handle(t, h, xeasReq(name, acctKey, xn, t0.Add(2*time.Minute)))
	if xres.Kind != KindXEAS {
		t.Fatal(xres.Kind)
	}
	xas := decodeRep(t, xrep, tagASRep, msgASRep, acctKey, xn, tagEncAS)
	if _, ok := xas.fields[2]; ok {
		t.Fatal("XEAS reply must not carry padata")
	}
	if len(xrep) != 550 {
		t.Errorf("XEAS reply %d bytes, the live reply was 550", len(xrep))
	}
	// The TGT is ours: it decrypts with the ticket key and names the account.
	tf, err := appSeqFields(xas.ticket, tagTicket)
	if err != nil {
		t.Fatal(err)
	}
	cipher, _ := encryptedData(tf[3].Raw)
	plain, err := rc4hmac.Decrypt(h.TicketKey, rc4hmac.UsageTicket, cipher)
	if err != nil {
		t.Fatal("TGT not decryptable with the ticket key")
	}
	inner, _ := appSeqFields(plain, tagEncTkt)
	if n, _ := principal(inner[3]); len(n) != 1 || n[0] != name {
		t.Fatalf("TGT principal %v", n)
	}
	if k, _ := keyValue(inner[1]); !bytes.Equal(k, xas.session) {
		t.Fatal("TGT session key differs from the enc-part key")
	}

	// TGS for sg/S0.
	tn := uint32(0x7b3e1d67)
	treq := tgsReq(name, xas.ticket, xas.session, tn, t0.Add(3*time.Minute), nil)
	trep, tres := handle(t, h, treq)
	if tres.Kind != KindTGS {
		t.Fatal(tres.Kind)
	}
	tgs := decodeRep(t, trep, tagTGSRep, msgTGSRep, xas.session, tn, tagEncTGS)
	d7 := decodeD7(t, tgs, rc4hmac.Derive(xas.session, tn))
	if !bytes.Equal(d7[0x24:0x28], []byte{10, 0, 2, 2}) {
		t.Fatalf("SG address %v", d7[0x24:0x28])
	}
	if binary.LittleEndian.Uint32(d7) != 0 {
		t.Fatal("D7 status not zero")
	}
	for i, b := range d7[0x5c:0x7c] {
		want := byte(0xff)
		switch i {
		case 0: // service 1: bits 2-3
			want = 0xf3
		case 5: // service 20: bits 0-1
			want = 0xfc
		}
		if b != want {
			t.Fatalf("service map byte %d = %#x, want %#x", i, b, want)
		}
	}
	if binary.LittleEndian.Uint64(d7[0xb0:]) != 1 {
		t.Fatal("D7 cookie")
	}
	for _, i := range []int{0x04, 0x28, 0x58, 0x7c, 0x98, 0x9c} {
		if d7[i] != 0 {
			t.Fatalf("D7 byte %#x not zero", i)
		}
	}
	if sn, _ := principal(tgs.part[10]); !equalStrings(sn, []string{"sg", "S0"}) {
		t.Fatalf("TGS sname %v", sn)
	}
	if len(trep) != 772 {
		t.Errorf("TGS reply %d bytes, the live reply was 772", len(trep))
	}
	// The service ticket is ours too and carries the new session key.
	tf2, _ := appSeqFields(tgs.ticket, tagTicket)
	if sn, _ := principal(tf2[2]); !equalStrings(sn, []string{"sg", "S0"}) {
		t.Fatalf("service ticket sname %v", sn)
	}
	c2, _ := encryptedData(tf2[3].Raw)
	p2, err := rc4hmac.Decrypt(h.TicketKey, rc4hmac.UsageTicket, c2)
	if err != nil {
		t.Fatal(err)
	}
	in2, _ := appSeqFields(p2, tagEncTkt)
	if k, _ := keyValue(in2[1]); !bytes.Equal(k, tgs.session) {
		t.Fatal("service ticket key differs from TGS enc-part key")
	}
	if s, e := mustTime(t, in2[6]), mustTime(t, in2[7]); !s.Equal(t0) || !e.Equal(t0.Add(time.Hour)) {
		t.Fatalf("service ticket validity %v %v", s, e)
	}
}

func mustTime(t *testing.T, v der.TLV) time.Time {
	t.Helper()
	at, err := der.ParseTime(v.Value)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestMACSRejections(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{1, 2, 3, 4, 5})
	req, _ := c.macsReq(t, &h.XMACS.PublicKey, 7, t0)
	db := req[bytes.Index(req, c.cert)-dbCertOff:]
	db = db[:dbLen]
	cases := []struct {
		name string
		off  int
		want string
	}{
		{"OAEP block", 0, "OAEP"},
		{"timestamp", dbTimeOff, "console signature"},
		{"serial", dbSerialOff + 3, "console signature"},
		{"console signature", dbSigOff + 5, "console signature"},
		{"certificate body", dbCertOff + 0x10, "CA signature"},
		{"certificate header", dbCertOff + 1, "certificate header"},
		{"CA signature", dbCertOff + 0xa8 + 3, "CA signature"},
	}
	for _, tc := range cases {
		reject(t, h, flip(t, req, db, tc.off), tc.want)
	}
	// Tampered CE: its MAC (the byte before the text) and its text.
	reject(t, h, flip(t, req, []byte(ceText[:20]), -1), "CE checksum")
	reject(t, h, flip(t, req, []byte(ceText[:20]), 5), "CE checksum")
	// Another CA signs a well-formed certificate: still refused.
	otherCA, _ := rsa.GenerateKey(rand.Reader, 2048)
	c2 := newConsole(t, otherCA, [5]byte{1, 2, 3, 4, 5})
	req2, _ := c2.macsReq(t, &h.XMACS.PublicKey, 8, t0)
	reject(t, h, req2, "CA signature")
	// cname not matching the certificate's console ID.
	c3 := newConsole(t, ca, [5]byte{1, 2, 3, 4, 6})
	req3, _ := c3.macsReq(t, &h.XMACS.PublicKey, 9, t0)
	wrong := bytes.Replace(req3, []byte("XE."+ConsoleDigits(c3.cert)), []byte("XE."+ConsoleDigits(c.cert)), 1)
	reject(t, h, wrong, "console id/cname mismatch")
	// A different XMACS key.
	otherX, _ := rsa.GenerateKey(rand.Reader, 2048)
	req4, _ := c.macsReq(t, &otherX.PublicKey, 10, t0)
	reject(t, h, req4, "OAEP")
	// Encrypted timestamp tampered (last cipher byte of padata 2).
	reject(t, h, flipPadata(req, PaEncTS), "timestamp checksum")
	if h.Accounts.Len() != 0 {
		t.Fatal("a rejected MACS provisioned an account")
	}
	// Record-only: foreign realm, foreign tag, garbage.
	for _, d := range [][]byte{
		kdcReqMsg(10, msgASReq, []paItem{{PaEncTS, []byte{1}}}, reqBody(clientPrincipal(10, "x"), "OTHER.REALM", []string{Krbtgt, "OTHER.REALM"}, 1)),
		{0x7e, 0x01, 0x00},
		{},
	} {
		rep, res, err := h.Handle(d)
		if err != nil || rep != nil || res.Kind != KindRecordOnly {
			t.Fatalf("record-only: %v %v %v", rep, res, err)
		}
	}
	if _, _, err := h.Handle([]byte{0x6a, 0x01}); err == nil {
		t.Fatal("truncated AS-REQ accepted")
	}
}

func TestXEASRejections(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{9, 9, 9, 9, 9})
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, 1, t0)
	rep, _ := handle(t, h, req)
	cb := decodeCB(t, decodeRep(t, rep, tagASRep, msgASRep, secret, 1, tagEncAS), secret, 1)
	name := ConsoleDigits(c.cert) + "@xbox.com"
	key := cb[68:84]

	good := xeasReq(name, key, 2, t0)
	handle(t, h, good)
	reject(t, h, xeasReq("000000000001@xbox.com", key, 3, t0), "unknown account")
	reject(t, h, xeasReq(name, rc4hmac.NewKey(), 4, t0), "CE checksum")
	reject(t, h, flip(t, good, []byte(ceText[:20]), 3), "CE checksum")
	reject(t, h, flipPadata(good, PaEncTS), "timestamp checksum")
	// Freshness: the clock moves 5 minutes past the timestamp.
	h.Now = func() time.Time { return t0.Add(5 * time.Minute) }
	reject(t, h, good, "outside 5 minutes")
	h.Now = func() time.Time { return t0.Add(-5 * time.Minute) }
	reject(t, h, good, "outside 5 minutes")
	h.Now = func() time.Time { return t0.Add(4*time.Minute + 59*time.Second) }
	handle(t, h, good)
	h.Now = func() time.Time { return t0 }
	// Padata set must be exactly D8, CE, 2.
	d8 := make([]byte, 20)
	pa := []paItem{{PaCE, ceBlock(rc4hmac.Derive(key, 0), ceText)}, {PaEncTS, encTimestamp(key, t0)}}
	body := reqBody(clientPrincipal(10, name), AccountRealm, []string{Krbtgt, AccountRealm}, 5)
	reject(t, h, kdcReqMsg(10, msgASReq, pa, body), "padata set")
	reject(t, h, kdcReqMsg(10, msgASReq, append(pa, paItem{PaD8, d8[:19]}), body), "D8 length")
	reject(t, h, kdcReqMsg(10, msgASReq, append(pa, paItem{PaD8, d8}, paItem{PaD8, d8}), body), "duplicate padata")
	// Wrong service.
	reject(t, h, kdcReqMsg(10, msgASReq, append(pa, paItem{PaD8, d8}), reqBody(clientPrincipal(10, name), AccountRealm, []string{"sg", "S0"}, 5)), "unexpected AS service")
	// Provenance flag cleared: refused even though the key is right.
	h.Accounts.Get(name).ConsoleSignatureVerified = false
	reject(t, h, good, "unverified account provenance")
	h.Accounts.Get(name).ConsoleSignatureVerified = true
	// Stored certificate no longer verifies (CA rotated).
	otherCA, _ := rsa.GenerateKey(rand.Reader, 2048)
	h.CA = &otherCA.PublicKey
	reject(t, h, good, "stored certificate")
}

func TestTGSRejections(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{5, 4, 3, 2, 1})
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, 1, t0)
	rep, _ := handle(t, h, req)
	cb := decodeCB(t, decodeRep(t, rep, tagASRep, msgASRep, secret, 1, tagEncAS), secret, 1)
	name := ConsoleDigits(c.cert) + "@xbox.com"
	key := cb[68:84]
	xrep, _ := handle(t, h, xeasReq(name, key, 2, t0))
	xas := decodeRep(t, xrep, tagASRep, msgASRep, key, 2, tagEncAS)
	tgt, session := xas.ticket, xas.session

	good := tgsReq(name, tgt, session, 3, t0, nil)
	handle(t, h, good)
	// Tampered AP-REQ authenticator, CE and D6 (each padata's last cipher byte).
	for pa, want := range map[uint64]string{PaAPReq: "authenticator checksum", PaCE: "CE checksum", PaD6: "D6 checksum"} {
		reject(t, h, flipPadata(good, pa), want)
	}
	// Body modified after the authenticator checksum was taken.
	reject(t, h, bytes.Replace(good, der.Time(till), der.Time(till.Add(time.Second)), 1), "request body checksum")
	// Wrong service, other realm.
	wrongSvc := bytes.Replace(good, der.String("S0"), der.String("S1"), 1)
	reject(t, h, wrongSvc, "only sg/S0")
	// Opaque (random) ticket like the oracle's first MACS tickets: not ours.
	reject(t, h, tgsReq(name, opaqueTicket(AccountRealm, []string{Krbtgt, AccountRealm}), session, 4, t0, nil), "not issued by this server")
	// Ticket under another server's ticket key.
	other := &Handler{TicketKey: rc4hmac.NewKey()}
	reject(t, h, tgsReq(name, other.authTicket(AccountRealm, []string{name}, []string{Krbtgt, AccountRealm}, session, t0), session, 5, t0, nil), "not issued by this server")
	// Ticket for a different (unknown) identity, signed by us.
	reject(t, h, tgsReq("000000000002@xbox.com", h.authTicket(AccountRealm, []string{"000000000002@xbox.com"}, []string{Krbtgt, AccountRealm}, session, t0), session, 6, t0, nil), "unknown ticket identity")
	// Authenticator identity not matching the ticket.
	reject(t, h, tgsReq("000000000002@xbox.com", tgt, session, 7, t0, nil), "authenticator identity")
	// Wrong session key for the authenticator.
	reject(t, h, tgsReq(name, tgt, rc4hmac.NewKey(), 8, t0, nil), "authenticator checksum")
	// User ids present: not implemented, refused.
	reject(t, h, tgsReq(name, tgt, session, 9, t0, func(d6 []byte, _ *[][]byte) { d6[d6UsersOff+3] = 1 }), "user TGS authentication")
	// Wrong D6 version.
	reject(t, h, tgsReq(name, tgt, session, 10, t0, func(d6 []byte, _ *[][]byte) { d6[0] = 5 }), "D6 version")
	// Authenticator subkey present.
	reject(t, h, tgsReq(name, tgt, session, 11, t0, func(_ []byte, a *[][]byte) {
		*a = append((*a)[:6], append([][]byte{der.Ctx(6, encKey(rc4hmac.NewKey()))}, (*a)[6:]...)...)
	}), "subkey")
	// Authenticator checksum type not MD5.
	reject(t, h, tgsReq(name, tgt, session, 12, t0, func(_ []byte, a *[][]byte) {
		(*a)[3] = der.Ctx(3, der.Seq(der.Ctx(0, der.Integer(1)), der.Ctx(1, der.Octet(make([]byte, 16)))))
	}), "body checksum type")
	// Stale authenticator, then expired ticket.
	h.Now = func() time.Time { return t0.Add(6 * time.Minute) }
	reject(t, h, good, "authenticator freshness")
	h.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	reject(t, h, tgsReq(name, tgt, session, 13, t0.Add(2*time.Hour), nil), "ticket validity")
	h.Now = func() time.Time { return t0.Add(-time.Second) }
	reject(t, h, tgsReq(name, tgt, session, 14, t0.Add(-time.Second), nil), "ticket validity")
	h.Now = func() time.Time { return t0 }
	// Provenance cleared after the TGT was issued.
	h.Accounts.Get(name).ConsoleSignatureVerified = false
	reject(t, h, good, "ticket account provenance")
	h.Accounts.Get(name).ConsoleSignatureVerified = true
	// Padata set.
	reject(t, h, kdcReqMsg(12, msgTGSReq, []paItem{{PaCE, []byte{1}}}, reqBody(nil, AccountRealm, []string{"sg", "S0"}, 15)), "padata set")
	handle(t, h, good)
}

// flipPadata returns a copy of a request with the last byte of the padata of
// type pa changed: a cipher byte, or the CE text's NUL. The [2] wrapper
// follows the [1] type marker inside the PA-DATA sequence.
func flipPadata(data []byte, pa uint64) []byte {
	bad := append([]byte{}, data...)
	marker := der.Ctx(1, der.Integer(pa))
	i := bytes.Index(bad, marker) + len(marker)
	bad[i+tlvLen(bad[i:])-1] ^= 1
	return bad
}

// tlvLen is the total length of the DER element at the start of b.
func tlvLen(b []byte) int {
	n, i := int(b[1]), 2
	if n&0x80 != 0 {
		z := n & 0x7f
		n = 0
		for _, c := range b[2 : 2+z] {
			n = n<<8 | int(c)
		}
		i += z
	}
	return i + n
}

func TestD7Record(t *testing.T) {
	rec := d7Record(mustAddr("203.0.113.9"))
	if len(rec) != D7Len || !bytes.Equal(rec[0x24:0x28], []byte{203, 0, 113, 9}) {
		t.Fatalf("%x", rec)
	}
	if rec[0x5c] != 0xf3 || rec[0x5c+5] != 0xfc || rec[0x5c+1] != 0xff || rec[0x7b] != 0xff {
		t.Fatalf("service map %x", rec[0x5c:0x7c])
	}
	if !bytes.Equal(rec[0xb0:0xb8], []byte{1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("cookie")
	}
}

func TestAccountRecordLayout(t *testing.T) {
	cert := make([]byte, CertLen)
	copy(cert[2:7], []byte{0x6f, 0x74, 0xc8, 0x86, 0x36})
	key := bytes.Repeat([]byte{0xab}, 16)
	rec := newAccountRecord(cert, key)
	if len(rec) != AccountLen {
		t.Fatal(len(rec))
	}
	// The live record from the dev store: id 0x0009006f74c88636 LE, then the strings.
	if !bytes.Equal(rec[:8], []byte{0x36, 0x86, 0xc8, 0x74, 0x6f, 0x00, 0x09, 0x00}) {
		t.Fatalf("id %x", rec[:8])
	}
	if string(rec[8:24]) != "478700668470\x00\x00\x00\x00" || string(rec[24:44]) != "xbox.com"+strings.Repeat("\x00", 12) ||
		string(rec[44:68]) != "XBOX.COM"+strings.Repeat("\x00", 16) || !bytes.Equal(rec[68:], key) {
		t.Fatalf("%x", rec)
	}
}

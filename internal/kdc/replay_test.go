package kdc

// Replay of the real firmware datagrams saved while the Python oracle served
// Wharf (scratch/wharf/run/logs/kdc-xetgs2 and kdc-asrep-final). These need
// the dev key material and run only when X360_KDC_TESTKEYS points at the keys
// directory; the captures are found relative to it (../run/logs).
//
// Replies contain random session keys, confounders and the time of day, so a
// saved reply is not compared byte for byte. Instead: every request is fully
// verified with the real keys, our reply has the same DER shape (tags and
// lengths) as the reply the firmware accepted, decrypts with the client's key,
// echoes the nonce, and the deterministic records (CB account record, D7
// service record) are byte-identical to the saved reply's.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openpak/x360-kdc/internal/rc4hmac"
)

type replay struct {
	h    *Handler
	logs string
}

func newReplay(t *testing.T) *replay {
	t.Helper()
	keys := os.Getenv("X360_KDC_TESTKEYS")
	if keys == "" {
		t.Skip("X360_KDC_TESTKEYS not set; skipping capture replay")
	}
	priv, err := LoadPrivateKey(filepath.Join(keys, "xmacs-dev-private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadPublicKey(filepath.Join(keys, "console-ca-public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tk, err := LoadTicketKey(filepath.Join(keys, "x360-ticket-key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	// Work on a copy of the account store: provisioning must never touch the dev file.
	src, err := os.ReadFile(filepath.Join(keys, "x360-dev-accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{XMACS: priv, CA: ca, Accounts: store, TicketKey: tk, SGAddress: mustAddr("10.0.2.2")}
	return &replay{h: h, logs: filepath.Join(keys, "..", "run", "logs")}
}

// load reads a capture and sets the handler clock to the moment it was received.
func (r *replay) load(t *testing.T, dir, name string) []byte {
	t.Helper()
	p := filepath.Join(r.logs, dir, name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("capture missing: %v", err)
	}
	fi, _ := os.Stat(p)
	at := fi.ModTime()
	r.h.Now = func() time.Time { return at }
	return b
}

// noSecrets fails if any logged attribute carries one of the given byte strings in hex.
func noSecrets(t *testing.T, res *Result, secrets ...[]byte) {
	t.Helper()
	for _, a := range res.Attrs {
		s := fmt.Sprint(a)
		for _, k := range secrets {
			if len(k) > 0 && strings.Contains(strings.ToLower(s), hex.EncodeToString(k)) {
				t.Fatalf("key material in log attribute %q", s)
			}
		}
	}
}

func TestReplayXETGS2(t *testing.T) {
	r := newReplay(t)
	const dir = "kdc-xetgs2"
	before := r.h.Accounts.Len()

	// MACS 1167 -> 545.
	req := r.load(t, dir, "req-000.bin")
	saved := r.load(t, dir, "rep-000.bin")
	kr, err := parseKDCReq(req, tagASReq, msgASReq)
	if err != nil {
		t.Fatal(err)
	}
	cname, _ := principal(kr.body[1])
	m, err := verifyMACS(r.h.XMACS, r.h.CA, kr, cname)
	if err != nil {
		t.Fatalf("live MACS request does not verify: %v", err)
	}
	rep, res := handle(t, r.h, req)
	noSecrets(t, res, m.secret)
	if len(rep) != len(saved) || shape(rep) != shape(saved) {
		t.Fatalf("MACS reply %d bytes %s\nsaved %d bytes %s", len(rep), shape(rep), len(saved), shape(saved))
	}
	ours := decodeRep(t, rep, tagASRep, msgASRep, m.secret, kr.nonce, tagEncAS)
	theirs := decodeRep(t, saved, tagASRep, msgASRep, m.secret, kr.nonce, tagEncAS)
	cb, cbSaved := decodeCB(t, ours, m.secret, kr.nonce), decodeCB(t, theirs, m.secret, kr.nonce)
	if !bytes.Equal(cb, cbSaved) {
		t.Fatalf("CB record differs from the one the firmware installed:\n%x\n%x", cb, cbSaved)
	}
	if res.Attrs[len(res.Attrs)-1] != false {
		t.Fatal("MACS replay should have reused the stored account")
	}
	acct := r.h.Accounts.Get(strings.TrimPrefix(cname[0], "XE.") + "@" + AccountDomain)
	if acct == nil {
		t.Fatal("account missing after MACS")
	}
	key, _ := acct.Key()
	if !bytes.Equal(key, cb[68:]) {
		t.Fatal("stored key is not the CB key")
	}

	// XEAS 353 -> 550.
	req = r.load(t, dir, "req-001.bin")
	saved = r.load(t, dir, "rep-001.bin")
	kr, _ = parseKDCReq(req, tagASReq, msgASReq)
	rep, res = handle(t, r.h, req)
	noSecrets(t, res, key)
	if res.Kind != KindXEAS || len(rep) != len(saved) || shape(rep) != shape(saved) {
		t.Fatalf("XEAS reply %v %d bytes %s\nsaved %d %s", res.Kind, len(rep), shape(rep), len(saved), shape(saved))
	}
	xas := decodeRep(t, rep, tagASRep, msgASRep, key, kr.nonce, tagEncAS)
	decodeRep(t, saved, tagASRep, msgASRep, key, kr.nonce, tagEncAS)
	if _, ok := xas.fields[2]; ok {
		t.Fatal("XEAS reply carries padata")
	}

	// TGS 841 -> 772. The TGT in the request was issued by the oracle with the same ticket key.
	req = r.load(t, dir, "req-002.bin")
	saved = r.load(t, dir, "rep-002.bin")
	kr, _ = parseKDCReq(req, tagTGSReq, msgTGSReq)
	ap, _ := appSeqFields(kr.padata[PaAPReq], tagAPReq)
	tf, _ := appSeqFields(ap[3].Raw, tagTicket)
	cipher, _ := encryptedData(tf[3].Raw)
	plain, err := rc4hmac.Decrypt(r.h.TicketKey, rc4hmac.UsageTicket, cipher)
	if err != nil {
		t.Fatalf("captured TGT does not open with the ticket key: %v", err)
	}
	inner, _ := appSeqFields(plain, tagEncTkt)
	session, _ := keyValue(inner[1])
	rep, res = handle(t, r.h, req)
	noSecrets(t, res, session, r.h.TicketKey, key)
	if res.Kind != KindTGS || len(rep) != len(saved) || shape(rep) != shape(saved) {
		t.Fatalf("TGS reply %v %d bytes %s\nsaved %d %s", res.Kind, len(rep), shape(rep), len(saved), shape(saved))
	}
	derived := rc4hmac.Derive(session, kr.nonce)
	tgs := decodeRep(t, rep, tagTGSRep, msgTGSRep, session, kr.nonce, tagEncTGS)
	tgsSaved := decodeRep(t, saved, tagTGSRep, msgTGSRep, session, kr.nonce, tagEncTGS)
	d7, d7Saved := decodeD7(t, tgs, derived), decodeD7(t, tgsSaved, derived)
	// The saved reply predates services added to D7Services; mark those
	// available in the saved record too so only the rest must match.
	for _, id := range D7Services {
		d7Saved[0x5c+id/4] &^= byte(3 << ((id % 4) * 2))
	}
	if !bytes.Equal(d7, d7Saved) {
		t.Fatalf("D7 differs from the record the firmware accepted:\n%x\n%x", d7, d7Saved)
	}
	if sn, _ := principal(tgs.part[10]); !equalStrings(sn, []string{"sg", "S0"}) {
		t.Fatalf("sname %v", sn)
	}
	// The D6 the firmware sent is logged in full; it carries no key.
	if !strings.Contains(fmt.Sprint(res.Attrs...), "d6") {
		t.Fatal("D6 not logged")
	}
	if r.h.Accounts.Len() != before {
		t.Fatal("replay changed the number of accounts")
	}
}

func TestReplayASRepFinal(t *testing.T) {
	r := newReplay(t)
	const dir = "kdc-asrep-final"
	// MACS 1167 -> 545: the first live-accepted reply. That oracle run issued a
	// random account key and did not persist it, so only the first 68 bytes of
	// the CB record (id, name, domain, realm) match the stored account.
	req := r.load(t, dir, "req-000.bin")
	saved := r.load(t, dir, "rep-000.bin")
	kr, _ := parseKDCReq(req, tagASReq, msgASReq)
	cname, _ := principal(kr.body[1])
	m, err := verifyMACS(r.h.XMACS, r.h.CA, kr, cname)
	if err != nil {
		t.Fatalf("live MACS request does not verify: %v", err)
	}
	rep, _ := handle(t, r.h, req)
	if len(rep) != len(saved) || shape(rep) != shape(saved) {
		t.Fatalf("MACS reply %d bytes %s\nsaved %d bytes %s", len(rep), shape(rep), len(saved), shape(saved))
	}
	cb := decodeCB(t, decodeRep(t, rep, tagASRep, msgASRep, m.secret, kr.nonce, tagEncAS), m.secret, kr.nonce)
	cbSaved := decodeCB(t, decodeRep(t, saved, tagASRep, msgASRep, m.secret, kr.nonce, tagEncAS), m.secret, kr.nonce)
	if !bytes.Equal(cb[:68], cbSaved[:68]) {
		t.Fatalf("CB identity fields differ:\n%x\n%x", cb[:68], cbSaved[:68])
	}
	// The six XEAS retries that followed used that unpersisted key: every one
	// must be refused at the CE check, since we do not hold the key.
	for i := 1; i <= 6; i++ {
		reject(t, r.h, r.load(t, dir, fmt.Sprintf("req-%03d.bin", i)), "CE checksum")
	}
}

package kdc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreProvisionPersistsWithMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cert := make([]byte, CertLen)
	copy(cert[2:7], []byte{1, 2, 3, 4, 5})
	a, issued, err := s.Provision(cert, t0)
	if err != nil || !issued || !a.ConsoleSignatureVerified {
		t.Fatalf("%v %v %+v", err, issued, a)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".pending"); !os.IsNotExist(err) {
		t.Fatal("pending file left behind")
	}
	// Same certificate: same account, nothing reissued.
	b, issued, err := s.Provision(cert, t0.Add(time.Minute))
	if err != nil || issued || b.Record != a.Record {
		t.Fatal("reuse failed")
	}
	// Reload from disk gives the same record and provenance.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	name := ConsoleDigits(cert) + "@" + AccountDomain
	got := s2.Get(name)
	if got == nil || got.Record != a.Record || got.Certificate != a.Certificate || !got.ConsoleSignatureVerified || got.IssuedAt != a.IssuedAt {
		t.Fatalf("reload: %+v", got)
	}
	k1, _ := a.Key()
	k2, _ := got.Key()
	if !bytes.Equal(k1, k2) || len(k1) != 16 {
		t.Fatal("key")
	}
	// A changed certificate for the same console replaces the account with a new key.
	cert2 := append([]byte{}, cert...)
	cert2[0x1c] = 'X'
	c, issued, err := s2.Provision(cert2, t0)
	if err != nil || !issued || c.Record == a.Record || c.Certificate == a.Certificate {
		t.Fatal("reissue on certificate change failed")
	}
	// An entry without provenance is refused, not upgraded.
	s2.Get(name).ConsoleSignatureVerified = false
	if _, _, err := s2.Provision(cert2, t0); err == nil {
		t.Fatal("unverified entry reused")
	}
}

func TestStoreUnknownAndBadFile(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "missing.json"))
	if err != nil || s.Len() != 0 || s.Get("x") != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	if _, err := OpenStore(bad); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

func TestTicketKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ticket.bin")
	k, err := LoadTicketKey(path)
	if err != nil || len(k) != 16 {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	k2, err := LoadTicketKey(path)
	if err != nil || !bytes.Equal(k, k2) {
		t.Fatal("reload")
	}
	os.WriteFile(path, make([]byte, 15), 0o600)
	if _, err := LoadTicketKey(path); err == nil {
		t.Fatal("15-byte key accepted")
	}
}

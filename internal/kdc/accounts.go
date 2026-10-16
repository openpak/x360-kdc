package kdc

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"openpak/x360-kdc/internal/rc4hmac"
)

// AccountLen is the 84-byte record MACS installs into the console
// (padata 0xCB plaintext):
//
//	0x00  8  LE account id: 0x0009 << 48 | console ID
//	0x08 16  NUL-padded account name (the 12 console digits)
//	0x18 20  NUL-padded domain  "xbox.com"
//	0x2C 24  NUL-padded realm   "XBOX.COM"
//	0x44 16  issued account key
const AccountLen = 84

const accountIDPrefix = 0x0009000000000000

// Account is one provisioned machine account, as persisted. Hex fields keep
// the file identical in shape to the oracle's, so dev material carries over.
type Account struct {
	Certificate              string  `json:"certificate"`                // 424 bytes, hex
	Record                   string  `json:"account"`                    // the 84-byte record, hex
	ConsoleSignatureVerified bool    `json:"console_signature_verified"` // provenance flag: issued after a verified MACS
	IssuedAt                 float64 `json:"issued_at"`                  // Unix seconds
	// Set when the account core is configured: the core's console link and
	// the OpenPak account it is paired to. The record is then a cache of the
	// core's answer, not the source of identity.
	CoreLinkID    string `json:"core_link_id,omitempty"`
	CoreAccountID string `json:"core_account_id,omitempty"`
}

// Key is the issued 16-byte account key, the last field of the record.
func (a *Account) Key() ([]byte, error) {
	rec, err := hex.DecodeString(a.Record)
	if err != nil || len(rec) != AccountLen {
		return nil, errors.New("account record")
	}
	return rec[AccountLen-rc4hmac.KeyLen:], nil
}

// Cert is the stored certificate bytes.
func (a *Account) Cert() ([]byte, error) {
	c, err := hex.DecodeString(a.Certificate)
	if err != nil || len(c) != CertLen {
		return nil, errors.New("stored certificate")
	}
	return c, nil
}

// Store is the JSON account file: a map from "digits@xbox.com" to Account.
// Writes go to <path>.pending with mode 0600, then rename.
type Store struct {
	path string
	mu   sync.Mutex
	m    map[string]*Account
}

// OpenStore loads path, or starts empty when it does not exist yet.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, m: map[string]*Account{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Get returns the account or nil.
func (s *Store) Get(name string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[name]
}

// Len is the number of accounts.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Provision returns the account for a console whose MACS request was fully
// verified. The same certificate reuses the issued key; a different
// certificate for the same console replaces the account with a fresh key. An
// existing entry for the same certificate without the verified-provenance
// flag is refused, never upgraded.
func (s *Store) Provision(cert []byte, now time.Time) (*Account, bool, error) {
	name := ConsoleDigits(cert) + "@" + AccountDomain
	certHex := hex.EncodeToString(cert)
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.m[name]; ok && a.Certificate == certHex {
		if !a.ConsoleSignatureVerified {
			return nil, false, errors.New("account provenance")
		}
		return a, false, nil
	}
	a := &Account{
		Certificate:              certHex,
		Record:                   hex.EncodeToString(newAccountRecord(cert, rc4hmac.NewKey())),
		ConsoleSignatureVerified: true,
		IssuedAt:                 float64(now.UnixNano()) / 1e9,
	}
	s.m[name] = a
	if err := s.save(); err != nil {
		delete(s.m, name)
		return nil, false, err
	}
	return a, true, nil
}

// BindCore records the account core's link and OpenPak account on an existing
// entry and persists it.
func (s *Store) BindCore(name, linkID, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[name]
	if !ok {
		return errors.New("account missing")
	}
	if a.CoreLinkID == linkID && a.CoreAccountID == accountID {
		return nil
	}
	prevL, prevA := a.CoreLinkID, a.CoreAccountID
	a.CoreLinkID, a.CoreAccountID = linkID, accountID
	if err := s.save(); err != nil {
		a.CoreLinkID, a.CoreAccountID = prevL, prevA
		return err
	}
	return nil
}

func newAccountRecord(cert, key []byte) []byte {
	rec := make([]byte, 0, AccountLen)
	rec = binary.LittleEndian.AppendUint64(rec, accountIDPrefix|ConsoleID(cert))
	rec = appendPadded(rec, ConsoleDigits(cert), 16)
	rec = appendPadded(rec, AccountDomain, 20)
	rec = appendPadded(rec, AccountRealm, 24)
	return append(rec, key...)
}

func appendPadded(b []byte, s string, n int) []byte {
	b = append(b, s...)
	return append(b, make([]byte, n-len(s))...)
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return err
	}
	pending := s.path + ".pending"
	f, err := os.OpenFile(pending, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(pending, s.path)
}

// LoadTicketKey reads the 16-byte ticket key, creating it (0600, random) when
// the file does not exist.
func LoadTicketKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		k := rc4hmac.NewKey()
		if _, err := f.Write(k); err != nil {
			f.Close()
			return nil, err
		}
		return k, f.Close()
	}
	if err != nil {
		return nil, err
	}
	if len(b) != rc4hmac.KeyLen {
		return nil, fmt.Errorf("%s: ticket key must be %d bytes, got %d", path, rc4hmac.KeyLen, len(b))
	}
	return b, nil
}

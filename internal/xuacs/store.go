package xuacs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenTTL is how long a 28-byte session token stays valid.
const TokenTTL = 24 * time.Hour

const (
	onlineHigh  = uint64(0x0009) << 48 // online XUID high word
	offlineHigh = uint64(0xE000) << 48 // offline XUID high word
	onlineMask  = uint64(1)<<40 - 1    // [guess] 40 account-derived low bits
	offlineMask = uint64(1)<<48 - 1
)

type consoleRec struct {
	Offline string `json:"offline"` // 16 hex digits
	Key     string `json:"key"`     // 32 hex digits, the XenonKey
}

type accountRec struct {
	Online   string                 `json:"online"` // 16 hex digits
	Consoles map[string]*consoleRec `json:"consoles,omitempty"`
}

type tokenRec struct {
	Account string    `json:"account"`
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

type stateFile struct {
	Accounts map[string]*accountRec `json:"accounts"`
	Tokens   map[string]*tokenRec   `json:"tokens"`
}

// Store keeps the session tokens and the profiles xuacs issued (online XUID per
// account; offline XUID and XenonKey per account and console). JSON, 0600,
// atomic rename. An empty path keeps everything in memory.
type Store struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
	d    stateFile
}

// OpenStore loads dir/xuacs.json, creating dir when missing.
func OpenStore(dir string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{now: now, d: stateFile{Accounts: map[string]*accountRec{}, Tokens: map[string]*tokenRec{}}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s.path = filepath.Join(dir, "xuacs.json")
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if s.d.Accounts == nil {
		s.d.Accounts = map[string]*accountRec{}
	}
	if s.d.Tokens == nil {
		s.d.Tokens = map[string]*tokenRec{}
	}
	return s, nil
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(&s.d, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// NewToken issues a random 28-byte token bound to the account.
func (s *Store) NewToken(account, email string) ([]byte, error) {
	tok := make([]byte, 28)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, t := range s.d.Tokens { // drop expired ones
		if now.After(t.Expires) {
			delete(s.d.Tokens, k)
		}
	}
	s.d.Tokens[hex.EncodeToString(tok)] = &tokenRec{Account: account, Email: email, Expires: now.Add(TokenTTL)}
	return tok, s.save()
}

// Token resolves a token to its account and sign-in email; ok is false when
// unknown or expired.
func (s *Store) Token(tok []byte) (account, email string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.d.Tokens[hex.EncodeToString(tok)]
	if t == nil || s.now().After(t.Expires) {
		return "", "", false
	}
	return t.Account, t.Email, true
}

// OnlineXUID returns the account's stored online XUID. When there is none it
// stores preferred (if non-zero, e.g. the subject of an existing x360 link)
// or derives one: 0x0009 high word and 40 low bits from SHA-256 of the account
// id, re-hashed with a counter on a collision with another account.
func (s *Store) OnlineXUID(account string, preferred uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.d.Accounts[account]; a != nil && a.Online != "" {
		return parseXUID(a.Online), nil
	}
	x := preferred
	if x == 0 {
		for n := uint32(0); ; n++ {
			h := sha256.Sum256(binary.BigEndian.AppendUint32([]byte("xuacs-online|"+account), n))
			x = onlineHigh | binary.BigEndian.Uint64(h[:8])&onlineMask
			if x&onlineMask != 0 && !s.usedLocked(x) {
				break
			}
		}
	}
	a := s.d.Accounts[account]
	if a == nil {
		a = &accountRec{}
		s.d.Accounts[account] = a
	}
	a.Online = fmt.Sprintf("%016x", x)
	return x, s.save()
}

func (s *Store) usedLocked(x uint64) bool {
	want := fmt.Sprintf("%016x", x)
	for _, a := range s.d.Accounts {
		if a.Online == want {
			return true
		}
	}
	return false
}

// Profile returns the offline XUID and the 16-byte XenonKey for an account on
// a console, creating them on first use (offline: 0xE000 + 48 random bits).
func (s *Store) Profile(account, console string) (offline uint64, key []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Accounts[account]
	if a == nil {
		a = &accountRec{}
		s.d.Accounts[account] = a
	}
	if a.Consoles == nil {
		a.Consoles = map[string]*consoleRec{}
	}
	c := a.Consoles[console]
	if c == nil {
		var b [8]byte
		var k [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, nil, err
		}
		if _, err := rand.Read(k[:]); err != nil {
			return 0, nil, err
		}
		c = &consoleRec{
			Offline: fmt.Sprintf("%016x", offlineHigh|binary.BigEndian.Uint64(b[:])&offlineMask),
			Key:     hex.EncodeToString(k[:]),
		}
		a.Consoles[console] = c
		if err := s.save(); err != nil {
			return 0, nil, err
		}
	}
	key, _ = hex.DecodeString(c.Key)
	return parseXUID(c.Offline), key, nil
}

func parseXUID(h string) uint64 {
	var x uint64
	fmt.Sscanf(h, "%x", &x)
	return x
}

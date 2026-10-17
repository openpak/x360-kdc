package gateway

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from the Python oracle (sg_data_check.iv_for).
func TestIVFor(t *testing.T) {
	for _, v := range []struct {
		seed string
		ctr  uint32
		iv   string
	}{
		{"0102030405060708", 1, "0102030405060708"},
		{"ffffffffffffffff", 2, "ffffffffffffffff"},
		{"0123456789abcdef", 65535, "3333bbbb3333bbbb"},
		{"deadbeefcafef00d", 0x12345, "0a39085eb45a95b3"},
		{"363709332fc38d5b", 1, "363709332fc38d5b"}, // sg3 client-to-server seed
		{"363709332fc38d5b", 2, "6c6e12665e861bb7"},
	} {
		if got := hex.EncodeToString(ivFor(unhex(t, v.seed), v.ctr)); got != v.iv {
			t.Errorf("ivFor(%s, %d) = %s, want %s", v.seed, v.ctr, got, v.iv)
		}
	}
}

func testKeys(t testing.TB) (dirKeys, dirKeys) {
	m := make([]byte, 100)
	for i := range m {
		m[i] = byte(i*7 + 3)
	}
	return derive(m)
}

func TestSealOpenRoundTrip(t *testing.T) {
	c2s, _ := testKeys(t)
	spi := []byte{0x80, 1, 2, 3}
	for n, body := range [][]byte{nil, {1}, bytes.Repeat([]byte{9}, 4), bytes.Repeat([]byte{7}, 300)} {
		pkt := seal(c2s, spi, uint32(n+1), 0x0b53, body)
		gotSPI, m, err := open(c2s, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotSPI, spi) || m.Type != 0x0b53 || m.Counter != uint32(n+1) || !bytes.Equal(m.Body, body) {
			t.Fatalf("round trip %d: %x %+v", n, gotSPI, m)
		}
		pkt[len(pkt)-1] ^= 1
		if _, _, err := open(c2s, pkt); err == nil || !strings.Contains(err.Error(), "ICV") {
			t.Fatalf("tampered ICV accepted: %v", err)
		}
	}
}

// A synthetic session through Gateway.Handle: ack for 0x0A53, silence for
// unknown types (session kept), close removes the session, counters per
// direction start at 1.
func TestHandleDataFlow(t *testing.T) {
	c2s, s2c := testKeys(t)
	src := netip.MustParseAddrPort("10.0.2.15:49152")
	now := time.Unix(1_700_000_000, 0)
	g := &Gateway{Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		sessions: map[netip.AddrPort]*Session{src: {Client: src, Account: "x", ClientSPI: []byte{1, 2, 3, 4},
			ServerSPI: []byte{0, 0xab, 0xc1, 0x23}, c2s: c2s, s2c: s2c, expires: now.Add(SessionTTL)}}}
	send := func(ctr uint32, typ uint16, body []byte) [][]byte {
		return g.Handle(seal(c2s, []byte{0x80, 0xab, 0xc1, 0x23}, ctr, typ, body), src)
	}
	out := send(1, TypeChallenge, make([]byte, 296))
	if len(out) != 1 {
		t.Fatal("no ack")
	}
	spi, m, err := open(s2c, out[0])
	if err != nil || m.Type != TypeAck || m.Counter != 1 || len(m.Body) != 0 || !bytes.Equal(spi, []byte{1, 2, 3, 4}) {
		t.Fatalf("ack: %x %+v %v", spi, m, err)
	}
	if out := send(2, 0x0b53, []byte{1, 2, 3}); out != nil || g.Sessions() != 1 {
		t.Fatal("unknown type must be silent and keep the session")
	}
	if out := g.Handle(seal(c2s, []byte{0, 0xde, 0xad, 0xbe}, 3, TypeChallenge, nil), src); out != nil {
		t.Fatal("foreign SPI answered")
	}
	if out := g.Handle(seal(c2s, []byte{0, 0xab, 0xc1, 0x23}, 3, TypeChallenge, nil), netip.MustParseAddrPort("10.0.2.16:1")); out != nil {
		t.Fatal("data from an unauthenticated address answered")
	}
	if out := send(4, TypeClose, make([]byte, 4)); out != nil || g.Sessions() != 0 {
		t.Fatal("close must drop the session without a reply")
	}
	if out := send(5, TypeChallenge, nil); out != nil {
		t.Fatal("data after close answered")
	}
}

func TestSessionExpiry(t *testing.T) {
	c2s, s2c := testKeys(t)
	src := netip.MustParseAddrPort("10.0.2.15:1")
	now := time.Unix(1_700_000_000, 0)
	g := &Gateway{Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		sessions: map[netip.AddrPort]*Session{src: {Client: src, ClientSPI: make([]byte, 4), ServerSPI: []byte{0, 1, 2, 3},
			c2s: c2s, s2c: s2c, expires: now.Add(SessionTTL)}}}
	now = now.Add(SessionTTL + time.Second)
	if out := g.Handle(seal(c2s, []byte{0, 1, 2, 3}, 1, TypeChallenge, nil), src); out != nil || g.Sessions() != 0 {
		t.Fatal("expired session still served")
	}
}

// 0x0553 after a user logon (SPI flag 0x20/0x40) is acknowledged with 0x0653
// echoing its 8-byte token, even when the AP-REQ inside cannot be read.
func TestTicketMessageAck(t *testing.T) {
	c2s, s2c := testKeys(t)
	src := netip.MustParseAddrPort("10.0.2.15:49152")
	now := time.Unix(1_700_000_000, 0)
	g := &Gateway{Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		TicketKey: make([]byte, 16),
		sessions: map[netip.AddrPort]*Session{src: {Client: src, Account: "x", ClientSPI: []byte{1, 2, 3, 4},
			ServerSPI: []byte{0, 0xab, 0xc1, 0x23}, c2s: c2s, s2c: s2c, expires: now.Add(SessionTTL)}}}
	body := append([]byte{0, 0, 0, 0x20, 1, 2, 3, 4, 5, 6, 7, 8}, 0x6e, 0)
	for i, flag := range []byte{0x20, 0x40} {
		out := g.Handle(seal(c2s, []byte{flag, 0xab, 0xc1, 0x23}, uint32(93+i), TypeTicket, body), src)
		if len(out) != 1 {
			t.Fatalf("flag %#x: no reply", flag)
		}
		_, m, err := open(s2c, out[0])
		if err != nil || m.Type != TypeTicketAck || !bytes.Equal(m.Body, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
			t.Fatalf("flag %#x: %+v %v", flag, m, err)
		}
	}
}

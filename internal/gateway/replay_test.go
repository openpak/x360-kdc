package gateway

// Replay of the real firmware datagrams saved while the Python oracle served
// Wharf (scratch/wharf/run/logs/sg3 and sg5). They need the dev key material
// and run only when X360_KDC_TESTKEYS points at the keys directory.

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/kdc"
	"openpak/x360-kdc/internal/rc4hmac"
)

type capture struct {
	logs, keys string
	ticketKey  []byte
	ca         *rsa.PublicKey
	accounts   string
}

func newCapture(t *testing.T) *capture {
	t.Helper()
	keys := os.Getenv("X360_KDC_TESTKEYS")
	if keys == "" {
		t.Skip("X360_KDC_TESTKEYS not set; skipping capture replay")
	}
	tk, err := kdc.LoadTicketKey(filepath.Join(keys, "x360-ticket-key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := kdc.LoadPublicKey(filepath.Join(keys, "console-ca-public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return &capture{logs: filepath.Join(keys, "..", "run", "logs"), keys: keys, ticketKey: tk, ca: ca,
		accounts: filepath.Join(keys, "x360-dev-accounts.json")}
}

// file reads a capture and returns it with the moment it was received.
func (c *capture) file(t *testing.T, dir, name string) ([]byte, time.Time) {
	t.Helper()
	p := filepath.Join(c.logs, dir, name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("capture missing: %v", err)
	}
	fi, _ := os.Stat(p)
	return b, fi.ModTime()
}

type sessionJSON struct {
	Key, Shared, Cnonce, Snonce, Material string
}

func (c *capture) session(t *testing.T, dir string) (s struct{ key, shared, cnonce, snonce, material []byte }) {
	t.Helper()
	b, _ := c.file(t, dir, "session.json")
	var j sessionJSON
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	s.key, s.shared, s.cnonce, s.snonce, s.material = unhex(t, j.Key), unhex(t, j.Shared), unhex(t, j.Cnonce), unhex(t, j.Snonce), unhex(t, j.Material)
	return
}

func (c *capture) verify(t *testing.T, dir string) (*initiation, *verified, []byte) {
	t.Helper()
	req, at := c.file(t, dir, "req-0012.bin")
	in, err := parseInitiation(req)
	if err != nil {
		t.Fatal(err)
	}
	store, err := kdc.OpenStore(c.accounts)
	if err != nil {
		t.Fatal(err)
	}
	v, err := verify(in, c.ticketKey, store, c.ca, at)
	if err != nil {
		t.Fatalf("%s initiation does not verify: %v", dir, err)
	}
	return in, v, req
}

// (a) the captured initiations verify: ticket, authenticator, HMAC, provenance.
func TestReplayInitiationVerifies(t *testing.T) {
	c := newCapture(t)
	for _, dir := range []string{"sg3", "sg6"} {
		in, v, req := c.verify(t, dir)
		if len(req) != 1336 || !bytes.Equal(v.key, c.session(t, dir).key) {
			t.Fatalf("%s: %d bytes, session key mismatch", dir, len(req))
		}
		if len(in.chunks) != 4 || in.chunks[0] != 0x5802 || in.chunks[2] != 0x5882 {
			t.Fatalf("%s chunks: %#x", dir, in.chunks)
		}
	}
}

func TestReplayInitiationRejections(t *testing.T) {
	c := newCapture(t)
	in, _, req := c.verify(t, "sg3")
	store, _ := kdc.OpenStore(c.accounts)
	_, at := c.file(t, "sg3", "req-0012.bin")
	tweak := func(i int) *initiation {
		b := bytes.Clone(req)
		b[i] ^= 1
		x, err := parseInitiation(b)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	reject := func(name string, in *initiation, key []byte, now time.Time, want string) {
		t.Helper()
		if _, err := verify(in, key, store, c.ca, now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", name, err, want)
		}
	}
	reject("clean", in, c.ticketKey, at.Add(time.Hour), "ticket validity")
	reject("foreign ticket key", in, bytes.Repeat([]byte{1}, 16), at, "not issued by this server")
	reject("stale authenticator", in, c.ticketKey, at.Add(10*time.Minute), "") // ticket still valid, authenticator not
	reject("tampered signed prefix", tweak(5+8), c.ticketKey, at, "HMAC")      // client nonce byte, covered by the HMAC
	if _, err := parseInitiation(req[:len(req)-5]); err == nil {
		t.Error("truncated initiation parsed")
	}
	if _, err := parseInitiation(append([]byte{1}, req[1:]...)); err == nil {
		t.Error("non-zero control framing parsed")
	}
	empty, _ := kdc.OpenStore(filepath.Join(t.TempDir(), "none.json"))
	if _, err := verify(in, c.ticketKey, empty, c.ca, at); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Errorf("unknown account: %v", err)
	}
	other, err := kdc.LoadPublicKey(filepath.Join(c.keys, "xmacs-dev-public.pem"))
	if err == nil {
		if _, err := verify(in, c.ticketKey, store, other, at); err == nil {
			t.Error("foreign CA accepted")
		}
	}
}

// (b) key schedule and data vectors against session.json.
func TestReplayKeyScheduleAndData(t *testing.T) {
	c := newCapture(t)
	for _, dir := range []string{"sg3", "sg6"} {
		s := c.session(t, dir)
		if got := keyMaterial(s.key, s.shared, s.cnonce, s.snonce); !bytes.Equal(got, s.material) {
			t.Fatalf("%s: material\n got %x\nwant %x", dir, got, s.material)
		}
	}
	s := c.session(t, "sg3")
	c2s, s2c := derive(s.material)
	p1, _ := c.file(t, "sg3", "req-0013.bin")
	p2, _ := c.file(t, "sg3", "req-0014.bin")
	spi1, m1, err := open(c2s, p1)
	if err != nil || m1.Type != 0x0153 || m1.Counter != 1 || len(m1.Body) != 0 || hex.EncodeToString(spi1) != "80abc123" {
		t.Fatalf("packet 1: %x %+v %v", spi1, m1, err)
	}
	spi2, m2, err := open(c2s, p2)
	if err != nil || m2.Type != 0x0053 || m2.Counter != 2 || hex.EncodeToString(m2.Body) != "00000000" || hex.EncodeToString(spi2) != "00abc123" {
		t.Fatalf("packet 2: %x %+v %v", spi2, m2, err)
	}
	if got := seal(c2s, spi1, 1, 0x0153, nil); !bytes.Equal(got, p1) {
		t.Fatalf("seal 1: %x != %x", got, p1)
	}
	if got := seal(c2s, spi2, 2, 0x0053, make([]byte, 4)); !bytes.Equal(got, p2) {
		t.Fatalf("seal 2: %x != %x", got, p2)
	}
	if _, _, err := open(s2c, p1); err == nil {
		t.Fatal("client packet opened with the server-to-client keys")
	}
}

// reply parts, as the client (81752AF8) reads them.
type parsedReply struct {
	chunks  map[uint16][]byte
	order   []uint16
	offsets map[uint16]int
	wire    []byte
}

func parseReply(t *testing.T, rep []byte) parsedReply {
	t.Helper()
	if !bytes.Equal(rep[:4], make([]byte, 4)) {
		t.Fatal("reply framing")
	}
	p := parsedReply{chunks: map[uint16][]byte{}, offsets: map[uint16]int{}, wire: rep[4:]}
	for off := 0; off < len(p.wire); {
		kind := binary.LittleEndian.Uint16(p.wire[off:])
		size := int(binary.LittleEndian.Uint16(p.wire[off+2:]))
		p.chunks[kind], p.offsets[kind] = p.wire[off+4:off+size], off
		p.order = append(p.order, kind)
		off += size
	}
	return p
}

// checkReply decodes a reply the way the client does and returns the decrypted core tail.
func checkReply(t *testing.T, name string, rep []byte, key, material, cnonce, clientSPI, snonce []byte) (core []byte, tail []byte) {
	t.Helper()
	p := parseReply(t, rep)
	if len(p.order) != 4 || p.order[0] != 0x5803 || p.order[1] != 0x5880 || p.order[2] != 0x5887 || p.order[3] != 0x5883 {
		t.Fatalf("%s: chunk order %#x", name, p.order)
	}
	core = p.chunks[0x5803]
	if len(core) != 60 || len(p.chunks[0x5880]) != 96 || len(p.chunks[0x5887]) != 0x118 {
		t.Fatalf("%s: sizes %d %d %d", name, len(core), len(p.chunks[0x5880]), len(p.chunks[0x5887]))
	}
	if !bytes.Equal(core[2:4], []byte{2, 0}) || !bytes.Equal(core[4:8], clientSPI) || core[8] != 0 || !bytes.Equal(core[12:20], cnonce) {
		t.Fatalf("%s: core header %x", name, core[:28])
	}
	if snonce != nil && !bytes.Equal(core[20:28], snonce) {
		t.Fatalf("%s: server nonce", name)
	}
	_, s2c := derive(material)
	var err error
	if tail, err = cbc(s2c.k, core[20:28], core[28:60], false); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(tail[26:]) != 300 || binary.LittleEndian.Uint16(tail[28:]) != 60 {
		t.Fatalf("%s: lifetimes in tail %x", name, tail)
	}
	rec, _ := cbc(s2c.k, core[20:28], p.chunks[0x5887], false)
	if !bytes.Equal(rec, make([]byte, 0x118)) {
		t.Fatalf("%s: 0x5887 record is not zero", name)
	}
	// AP-REP checksum: HMAC-SHA1(key, chunks before 0x5883).
	ap, err := kdc.AppSeqFields(p.chunks[0x5883], 0x6f)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := kdc.EncryptedData(ap[2].Raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rc4hmac.Decrypt(key, 12, cipher)
	if err != nil {
		t.Fatalf("%s: AP-REP enc-part: %v", name, err)
	}
	part, err := kdc.AppSeqFields(plain, 0x7b)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := der.Fields(part[2].Value)
	want := hmacSHA1(key, p.wire[:p.offsets[0x5883]])
	if !bytes.Equal(ck[0].Value, []byte{0xff, 0x7d}) || !bytes.Equal(ck[1].Value, want) {
		t.Fatalf("%s: AP-REP checksum", name)
	}
	return core, tail
}

// (c) our reply builder against the reply the firmware accepted.
func TestReplayReply(t *testing.T) {
	c := newCapture(t)
	for _, dir := range []string{"sg3", "sg6"} {
		s := c.session(t, dir)
		in, v, _ := c.verify(t, dir)
		saved, _ := c.file(t, dir, "rep-0012.bin")
		client := netip.MustParseAddr("10.0.2.15")
		// The saved reply itself decodes with session.json (self-check of the decoder).
		wantChunks := 4
		if dir == "sg3" {
			wantChunks = 3 // the first oracle run sent no 0x5887
		}
		if got := len(parseReply(t, saved).order); got != wantChunks {
			t.Fatalf("%s: saved reply has %d chunks", dir, got)
		}
		if dir == "sg3" {
			continue
		}
		savedCore, savedTail := checkReply(t, dir+" saved", saved, s.key, s.material, s.cnonce, in.clientSPI, s.snonce)
		// Ours, from a private we choose: the shared secret is recomputed from the client's public.
		priv := new(big.Int).SetBytes(bytes.Repeat([]byte{0x5a}, 96))
		params := replyParams{private: priv, snonce: s.snonce, spi: []byte{0, 0xab, 0xc1, 0x23}}
		rep, material, err := in.reply(v, client, params)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep) != len(saved) {
			t.Fatalf("%s: reply %d bytes, saved %d", dir, len(rep), len(saved))
		}
		core, tail := checkReply(t, dir+" ours", rep, v.key, material, s.cnonce, in.clientSPI, s.snonce)
		// Identical apart from the random fields: DH public, SPI, nonce use and the encrypted tail/AP-REP.
		if !bytes.Equal(core[:28], savedCore[:28]) && !bytes.Equal(core[:8], savedCore[:8]) {
			t.Fatalf("%s: core header differs", dir)
		}
		if !bytes.Equal(core[12:28], savedCore[12:28]) || !bytes.Equal(tail[26:30], savedTail[26:30]) || !bytes.Equal(tail[:4], []byte{10, 0, 2, 15}) {
			t.Fatalf("%s: core/tail differ from the accepted reply\nours %x\nsaved %x", dir, tail, savedTail)
		}
		if shape := func(b []byte) string { return hex.EncodeToString(b[:4]) }; shape(rep) != shape(saved) {
			t.Fatal("framing differs")
		}
		// Shared secret really is g^(a*b): the saved private is unknown, so check our own side.
		shared := leBytes(new(big.Int).Exp(leInt(in.public), priv, dhPrime), 96)
		if !bytes.Equal(material, keyMaterial(v.key, shared, s.cnonce, s.snonce)) {
			t.Fatal("material does not follow from the DH secret")
		}
	}
}

// End to end through Gateway.Handle with the captured sg6 initiation, then the
// captured data packets re-keyed to the new session's material is impossible
// (random server private), so the data path runs through the saved material.
func TestReplayHandleSG6(t *testing.T) {
	c := newCapture(t)
	_, at := c.file(t, "sg6", "req-0012.bin")
	req, _ := c.file(t, "sg6", "req-0012.bin")
	var logs strings.Builder
	src := netip.MustParseAddrPort("10.0.2.15:49300")
	g := &Gateway{TicketKey: c.ticketKey, AccountsPath: c.accounts, CA: c.ca, Now: func() time.Time { return at },
		Log: slog.New(slog.NewTextHandler(&logs, nil))}
	out := g.Handle(req, src)
	if len(out) != 1 || len(out[0]) != 571 || g.Sessions() != 1 {
		t.Fatalf("initiation: %d replies, sessions %d\n%s", len(out), g.Sessions(), logs.String())
	}
	if len(g.Handle(req[:100], src2(src))) != 0 {
		t.Fatal("truncated initiation answered")
	}
	// Reply core: [4:8] client SPI echo, [8:12] server SPI (0 + 3 random bytes, never all-zero).
	spi := out[0][4+4+8 : 4+4+12]
	if !bytes.Equal(out[0][4+4+4:4+4+8], req[4+4+4:4+4+8]) {
		t.Fatalf("client SPI echo %x", out[0][4+4+4:4+4+8])
	}
	if spi[0] != 0 || bytes.Equal(spi[1:], []byte{0, 0, 0}) {
		t.Fatalf("server SPI %x", spi)
	}
	s := g.sessions[src]
	if s == nil || !bytes.Equal(s.ServerSPI, spi) || !bytes.Equal(s.ClientSPI, req[4+4+4:4+4+4+4]) {
		t.Fatal("session SPIs")
	}
	if strings.Contains(logs.String(), hex.EncodeToString(s.c2s.k)) || strings.Contains(logs.String(), hex.EncodeToString(s.s2c.k)) {
		t.Fatal("key material in log")
	}
	// Second initiation from the same address replaces the session; a different one gets a different SPI.
	out2 := g.Handle(req, netip.MustParseAddrPort("10.0.2.16:49301"))
	if len(out2) != 1 || bytes.Equal(out2[0][16:20], spi) || g.Sessions() != 2 {
		t.Fatal("second session")
	}

	// Data path with the captured material: sg6 packets in the oracle's order.
	m := c.session(t, "sg6")
	c2s, s2c := derive(m.material)
	s.c2s, s.s2c = c2s, s2c
	s.ServerSPI = []byte{0, 0xab, 0xc1, 0x23}
	p13, _ := c.file(t, "sg6", "req-0013.bin")
	spi13, m13, err := open(c2s, p13)
	if err != nil {
		t.Fatalf("0x0A53 packet: %v", err)
	}
	t.Logf("sg6 req-0013: spi %x type %#x ctr %d body %d bytes", spi13, m13.Type, m13.Counter, len(m13.Body))
	if m13.Type != TypeChallenge || len(m13.Body) != 296 {
		t.Fatalf("0x0A53 shape: %#x len %d", m13.Type, len(m13.Body))
	}
	s.ServerSPI = append([]byte{spi13[0] & 0x7f}, spi13[1:]...)
	ack := g.Handle(p13, src)
	if len(ack) != 1 {
		t.Fatalf("no 0x0153 for the 0x0A53 packet\n%s", logs.String())
	}
	_, am, err := open(s2c, ack[0])
	if err != nil || am.Type != TypeAck || am.Counter != 1 {
		t.Fatalf("ack: %+v %v", am, err)
	}
	for _, n := range []string{"req-0014.bin", "req-0015.bin", "req-0016.bin"} {
		p, _ := c.file(t, "sg6", n)
		if len(p) != 36 {
			t.Fatalf("%s is %d bytes", n, len(p))
		}
		if _, _, err := open(c2s, p); err == nil {
			t.Fatalf("%s verifies with the data formula", n)
		}
		if g.Handle(p, src) != nil || g.Sessions() != 2 {
			t.Fatalf("%s must be logged as unverifiable and keep the session", n)
		}
	}
	if !strings.Contains(logs.String(), "unverifiable data") {
		t.Fatal("unverifiable packets not logged")
	}
	p17, _ := c.file(t, "sg6", "req-0017.bin")
	if g.Handle(p17, src) != nil || g.Sessions() != 1 {
		t.Fatalf("0x0053 close did not end the session\n%s", logs.String())
	}
}

func src2(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr(), a.Port()+7) }

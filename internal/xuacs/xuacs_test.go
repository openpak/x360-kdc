package xuacs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"openpak/x360-kdc/internal/accountcore"
)

// ---- fake account core (gRPC framing over cleartext HTTP/2) ----

func pbStr(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	b = binary.AppendUvarint(b, uint64(field)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func pbVar(b []byte, field int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3)
	return binary.AppendUvarint(b, v)
}

func pbParse(b []byte) map[int]string {
	m := map[int]string{}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		b = b[n:]
		if tag&7 == 0 {
			_, n := binary.Uvarint(b)
			b = b[n:]
			continue
		}
		l, n := binary.Uvarint(b)
		m[int(tag>>3)] = string(b[n : n+int(l)])
		b = b[n+int(l):]
	}
	return m
}

type fakeCore struct {
	mu    sync.Mutex
	links map[string]*accountcore.Link // namespace/subject
	codes map[string]string
}

func (f *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := func(code int) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(code))
	}
	raw, _ := io.ReadAll(r.Body)
	in := pbParse(raw[5:])
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	link := func(l *accountcore.Link) []byte {
		var o []byte
		o = pbStr(o, 1, l.LinkID)
		o = pbStr(o, 2, l.AccountID)
		o = pbVar(o, 3, uint64(l.State))
		o = pbStr(o, 4, l.SubjectID)
		return pbStr(o, 5, f.codes[l.LinkID])
	}
	switch strings.TrimPrefix(r.URL.Path, "/openpak.account.v1.") {
	case "Identity/VerifyPassword":
		switch {
		case in[3] == "ann@example.org" && in[4] == "secret12":
			out = pbVar(pbStr(nil, 1, "A-ann"), 2, 1)
		case in[3] == "bob@example.org" && in[4] == "secret12":
			out = pbVar(pbStr(nil, 1, "A-bob"), 2, 1)
		default:
			status(accountcore.CodeUnauthenticated)
			return
		}
	case "Links/GetActiveLinkByAccount":
		for _, l := range f.links {
			if l.AccountID == in[2] && strings.HasPrefix(l.SubjectID, "0009") && l.State == accountcore.StateActive {
				out = link(l)
			}
		}
		if out == nil {
			status(accountcore.CodeNotFound)
			return
		}
	case "Links/GetLinkBySubject":
		l := f.links[in[1]+"/"+in[2]]
		if l == nil {
			status(accountcore.CodeNotFound)
			return
		}
		out = link(l)
	case "Links/ReserveLink":
		k := in[2] + "/" + in[3]
		if f.links[k] == nil {
			f.links[k] = &accountcore.Link{LinkID: "link-" + k, AccountID: in[1], SubjectID: in[3], State: accountcore.StatePending}
		}
		out = pbStr(nil, 1, f.links[k].LinkID)
	case "Links/ActivateLink":
		for _, l := range f.links {
			if l.LinkID == in[1] {
				l.State = accountcore.StateActive
			}
		}
		out = pbVar(nil, 1, 2)
	case "Links/SetLinkPublicCode":
		f.codes[in[1]] = in[2]
	default:
		status(12)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	fr := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(out)))
	w.Write(append(fr, out...))
	status(0)
}

// ---- harness ----

type rig struct {
	t    *testing.T
	core *fakeCore
	h    *Handler
	srv  *httptest.Server
	now  time.Time
}

func newRig(t *testing.T, dir string) *rig {
	t.Helper()
	fc := &fakeCore{links: map[string]*accountcore.Link{}, codes: map[string]string{}}
	cs := httptest.NewUnstartedServer(fc)
	cs.Config.Protocols = new(http.Protocols)
	cs.Config.Protocols.SetUnencryptedHTTP2(true)
	cs.Start()
	t.Cleanup(cs.Close)
	cl, err := accountcore.New(cs.URL, "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, core: fc, now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	st, err := OpenStore(dir, func() time.Time { return r.now })
	if err != nil {
		t.Fatal(err)
	}
	r.h = &Handler{Core: CoreClient{Client: cl}, Key: key, Store: st, Now: func() time.Time { return r.now }}
	r.srv = httptest.NewServer(r.h)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) post(path string, body []byte, hdr ...string) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequest("POST", r.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "xon/5")
	req.Header.Set("X-Schema-Ver", "6.5")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && resp.Header.Get("Content-Type") != "xon/5" {
		r.t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, b
}

func lv(b []byte, v []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

type proxyParamsReply struct {
	blob []byte
	pub  *rsa.PublicKey
	tail []byte
}

func (r *rig) params() proxyParamsReply {
	r.t.Helper()
	st, b := r.post(PathProxyParams, []byte{0, 0, 0, 0})
	if st != 200 {
		r.t.Fatalf("0x64A status %d", st)
	}
	n := int(binary.LittleEndian.Uint16(b))
	blob := b[2 : 2+n]
	rest := b[2+n:]
	e := int(binary.LittleEndian.Uint32(rest))
	if binary.LittleEndian.Uint16(rest[4:]) != 256 || len(rest) != 4+2+256+20 {
		r.t.Fatalf("0x64A layout: %d bytes", len(rest))
	}
	return proxyParamsReply{blob, &rsa.PublicKey{N: new(big.Int).SetBytes(rest[6 : 6+256]), E: e}, rest[6+256:]}
}

// loginBody is what the applet builds (notes section 5, "0x608 crypto").
func loginBody(t *testing.T, p proxyParamsReply, email, pw string, ts time.Time, mutate func(pt []byte)) []byte {
	t.Helper()
	k := make([]byte, 24)
	rand.Read(k)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, p.pub, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt := append(bytes.Repeat([]byte{byte(20 - len(pw))}, 20), ts.UTC().Format(timestampLayout)...)
	copy(pt, pw)
	if mutate != nil {
		mutate(pt)
	}
	pwBlob, _ := des3CBC(k, pt, false)
	proxyEnc, _ := des3CBC(k, p.blob, false)
	if len(pwBlob) != 48 {
		t.Fatalf("pw blob %d", len(pwBlob))
	}
	var b []byte
	b = lv(b, []byte(email))
	b = lv(b, wrapped)
	b = lv(b, pwBlob)
	b = lv(b, proxyEnc)
	return binary.LittleEndian.AppendUint32(b, 0)
}

func (r *rig) login(email, pw string) (int, []byte) {
	return r.post(PathLogin, loginBody(r.t, r.params(), email, pw, r.now, nil))
}

func recoverBody(machine uint64, tok []byte, xuid uint64) []byte {
	b := binary.LittleEndian.AppendUint64(nil, machine)
	b = append(b, tok...)
	b = binary.LittleEndian.AppendUint64(b, xuid)
	return append(b, 0)
}

// ---- tests ----

func TestFullFlow(t *testing.T) {
	r := newRig(t, "")

	// 0x645
	body := append([]byte{0x10, 0}, "ann@example.org\x00"...)
	if st, b := r.post(PathMemberExists, body); st != 200 || !bytes.Equal(b, []byte{1}) {
		t.Fatalf("0x645: %d %x", st, b)
	}
	// wrong password, then right one
	if st, _ := r.login("ann@example.org", "wrongpw12"); st != 401 {
		t.Fatalf("wrong password: %d", st)
	}
	st, tok := r.login("ann@example.org", "secret12")
	if st != 200 || len(tok) != 28 {
		t.Fatalf("0x608: %d %x", st, tok)
	}
	// 0x60E
	st, b := r.post(PathGamertag, tok)
	if st != 200 {
		t.Fatalf("0x60E: %d", st)
	}
	xuid := binary.LittleEndian.Uint64(b)
	if xuid>>48 != 0x0009 || xuid&(1<<48-1) == 0 {
		t.Fatalf("online XUID %016x", xuid)
	}
	n := int(binary.LittleEndian.Uint16(b[8:]))
	tag := string(b[10 : 10+n-1])
	if tag != "ann" || b[len(b)-1] != 0 || len(b) != 10+n {
		t.Fatalf("gamertag reply %x", b)
	}
	if _, b2 := r.post(PathGamertag, tok); !bytes.Equal(b, b2) {
		t.Fatal("0x60E not stable")
	}
	// 0x624, 0x1707
	ub := binary.LittleEndian.AppendUint64(nil, xuid)
	ub = lv(ub, append([]byte(tag), 0))
	if st, b := r.post(PathUserType, ub); st != 200 || !bytes.Equal(b, []byte{2}) {
		t.Fatalf("0x624: %d %x", st, b)
	}
	fb := binary.LittleEndian.AppendUint64(nil, xuid)
	fb = binary.LittleEndian.AppendUint16(fb, 1)
	fb = append(fb, tok...)
	if st, b := r.post(PathFamily, fb); st != 200 || !bytes.Equal(b, []byte{0, 0}) {
		t.Fatalf("0x1707: %d %x", st, b)
	}
	// 0x63F enrols
	acct := "123456789012@xbox.com"
	st, rec := r.post(PathRecover, recoverBody(0x1111, tok, xuid), "X-X360-Account", acct)
	if st != 200 {
		t.Fatalf("0x63F: %d %s", st, rec)
	}
	if binary.LittleEndian.Uint64(rec) != xuid {
		t.Fatal("online XUID in 0x63F")
	}
	off := binary.LittleEndian.Uint64(rec[8:])
	if off>>56 != 0xE0 {
		t.Fatalf("offline XUID %016x", off)
	}
	if len(rec[16:32]) != 16 {
		t.Fatal("key")
	}
	rest := rec[32:]
	var got []string
	for i := 0; i < 3; i++ {
		l := int(binary.LittleEndian.Uint16(rest))
		got = append(got, string(rest[2:2+l-1]))
		if rest[1+l] != 0 {
			t.Fatal("string not NUL terminated")
		}
		rest = rest[2+l:]
	}
	if len(rest) != 0 || strings.Join(got, "|") != "ann|xbox.com|XBOX.COM" {
		t.Fatalf("strings %v rest %x", got, rest)
	}
	c := r.core.links["x360-console/123456789012"]
	u := r.core.links["x360/"+hex16(xuid)]
	if c == nil || c.AccountID != "A-ann" || c.State != accountcore.StateActive || u == nil || u.State != accountcore.StateActive {
		t.Fatalf("links %+v %+v", c, u)
	}
	if r.core.codes[u.LinkID] != "ann" {
		t.Fatalf("public code %q", r.core.codes[u.LinkID])
	}
	// stable on repeat
	if _, rec2 := r.post(PathRecover, recoverBody(0x1111, tok, xuid), "X-X360-Account", acct); !bytes.Equal(rec, rec2) {
		t.Fatal("0x63F not stable per account+console")
	}
	// another console gets another offline XUID/key
	_, rec3 := r.post(PathRecover, recoverBody(0x1111, tok, xuid), "X-X360-Account", "999999999999@xbox.com")
	if bytes.Equal(rec[8:32], rec3[8:32]) {
		t.Fatal("offline XUID/key must differ per console")
	}
	// the profile link now decides the XUID: a fresh store sees the same one via the core
	r2 := *r
	r2.h = &Handler{Core: r.h.Core, Key: r.h.Key, Store: mustStore(t, "", r), Now: r.h.Now}
	r2.srv = httptest.NewServer(r2.h)
	defer r2.srv.Close()
	_, tok2 := r2.login("ann@example.org", "secret12")
	if _, b3 := r2.post(PathGamertag, tok2); !bytes.Equal(b, b3) {
		t.Fatalf("XUID/gamertag changed with a fresh store: %x vs %x", b3, b)
	}

	// another account may not take the console or the 0x63F with a foreign XUID
	_, btok := r.login("bob@example.org", "secret12")
	_, bg := r.post(PathGamertag, btok)
	bx := binary.LittleEndian.Uint64(bg)
	if bx == xuid {
		t.Fatal("two accounts share an XUID")
	}
	if st, _ := r.post(PathRecover, recoverBody(1, btok, bx), "X-X360-Account", acct); st != 403 {
		t.Fatalf("console owned by another account: %d", st)
	}
	if st, _ := r.post(PathRecover, recoverBody(1, btok, xuid), "X-X360-Account", "555555555555@xbox.com"); st != 403 {
		t.Fatalf("foreign XUID: %d", st)
	}
	if st, _ := r.post(PathRecover, recoverBody(1, make([]byte, 28), bx)); st != 401 {
		t.Fatalf("unknown token: %d", st)
	}
}

func hex16(x uint64) string {
	s := strconv.FormatUint(x, 16)
	return strings.Repeat("0", 16-len(s)) + s
}

func mustStore(t *testing.T, dir string, r *rig) *Store {
	s, err := OpenStore(dir, func() time.Time { return r.now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoginChecks(t *testing.T) {
	r := newRig(t, "")
	email := "ann@example.org"
	p := r.params()
	if st, _ := r.post(PathLogin, loginBody(t, p, email, "secret12", r.now.Add(-6*time.Minute), nil)); st != 403 {
		t.Fatalf("skew: %d", st)
	}
	if st, _ := r.post(PathLogin, loginBody(t, p, email, "secret12", r.now.Add(4*time.Minute), nil)); st != 200 {
		t.Fatalf("skew within 5 minutes: %d", st)
	}
	fake := proxyParamsReply{blob: bytes.Repeat([]byte{7}, 32), pub: p.pub}
	if st, _ := r.post(PathLogin, loginBody(t, fake, email, "secret12", r.now, nil)); st != 403 {
		t.Fatalf("proxy blob we did not issue: %d", st)
	}
	if st, _ := r.post(PathLogin, loginBody(t, p, email, "secret12", r.now, func(pt []byte) { pt[18] ^= 1 })); st != 400 {
		t.Fatalf("broken padding: %d", st)
	}
	if st, _ := r.post(PathLogin, []byte{1, 2, 3}); st != 400 {
		t.Fatalf("garbage: %d", st)
	}
	// expired proxy blob
	r.now = r.now.Add(proxyTTL + time.Second)
	if st, _ := r.post(PathLogin, loginBody(t, p, email, "secret12", r.now, nil)); st != 403 {
		t.Fatalf("expired proxy blob: %d", st)
	}
	// expired token
	r.now = r.now.Add(-proxyTTL)
	_, tok := r.login(email, "secret12")
	r.now = r.now.Add(TokenTTL + time.Second)
	if st, _ := r.post(PathGamertag, tok); st != 401 {
		t.Fatalf("expired token: %d", st)
	}
}

func TestParamsAreFresh(t *testing.T) {
	r := newRig(t, "")
	a, b := r.params(), r.params()
	if bytes.Equal(a.blob, b.blob) || len(a.blob) != 32 || a.pub.E != 65537 || a.pub.N.Cmp(r.h.Key.N) != 0 {
		t.Fatal("proxy params")
	}
	if sum := sha1.Sum(r.h.Key.N.FillBytes(make([]byte, 256))); !bytes.Equal(a.tail, sum[:]) {
		t.Fatal("tail")
	}
}

func TestRecoverVariantsAndErrors(t *testing.T) {
	r := newRig(t, "")
	if st, _ := r.post(PathRecover, make([]byte, 60)); st != 501 {
		t.Fatalf("0x649 variant: %d", st)
	}
	if st, _ := r.post(PathMemberExists, []byte{0, 0}); st != 400 {
		t.Fatalf("empty email: %d", st)
	}
	if st, _ := r.post("/xuacs/Nope.ashx", nil); st != 404 {
		t.Fatalf("unknown path: %d", st)
	}
	if st, _ := r.post(PathGamertag, []byte{1}); st != 400 {
		t.Fatalf("short token: %d", st)
	}
	// no console header: machine id digits are the fallback
	_, tok := r.login("ann@example.org", "secret12")
	_, g := r.post(PathGamertag, tok)
	x := binary.LittleEndian.Uint64(g)
	if st, _ := r.post(PathRecover, recoverBody(0x1234567890ABCDEF, tok, x)); st != 200 {
		t.Fatalf("fallback console: %d", st)
	}
	if r.core.links["x360-console/"+fmtDigits(0x1234567890ABCDEF)] == nil {
		t.Fatal("machine id fallback link missing")
	}
}

func fmtDigits(m uint64) string {
	s := strconv.FormatUint(m%1_000_000_000_000, 10)
	return strings.Repeat("0", 12-len(s)) + s
}

func TestStorePersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	r := newRig(t, dir)
	_, tok := r.login("ann@example.org", "secret12")
	_, g := r.post(PathGamertag, tok)
	x := binary.LittleEndian.Uint64(g)
	off, key, err := r.h.Store.Profile("A-ann", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "xuacs.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	s2 := mustStore(t, dir, r)
	if _, _, ok := s2.Token(tok); !ok {
		t.Fatal("token lost on reload")
	}
	if x2, _ := s2.OnlineXUID("A-ann", 0); x2 != x {
		t.Fatal("online XUID lost")
	}
	if o2, k2, _ := s2.Profile("A-ann", "123456789012"); o2 != off || !bytes.Equal(k2, key) || len(key) != 16 {
		t.Fatal("profile lost")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k", "rsa.pem")
	k, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || k2.N.Cmp(k.N) != 0 {
		t.Fatal("reload", err)
	}
}

func TestGamertagFrom(t *testing.T) {
	for in, want := range map[string]string{"ann@x.org": "ann", "9lives_cat.x@x": "livescatx", "averyveryverylongname@x": "averyveryverylo", "123@x": "Player0001"} {
		if got := gamertagFrom(in, 1); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

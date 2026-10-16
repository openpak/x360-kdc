package accountcore

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

const testKey = "internal-key"

// fakeCore implements the three Links RPCs the KDC uses, in gRPC framing over
// cleartext HTTP/2, with the core's semantics (unknown subject -> NotFound,
// activate only from pending).
type fakeCore struct {
	mu    sync.Mutex
	links map[string]*Link // by namespace + "/" + subject
	codes map[string]string
	calls []string
	key   string
}

func (f *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := func(code int, msg string) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(code))
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", msg)
	}
	if r.Header.Get("X-Internal-Key") != f.key || r.Header.Get("Content-Type") != "application/grpc" {
		status(CodeUnauthenticated, "missing internal credentials")
		return
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) < 5 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		status(3, "bad frame")
		return
	}
	in := parseFields(body[5:])
	f.mu.Lock()
	defer f.mu.Unlock()
	method := r.URL.Path
	f.calls = append(f.calls, method)
	var out pb
	switch method {
	case linksService + "GetLinkBySubject":
		l := f.links[in.str(1)+"/"+in.str(2)]
		if l == nil {
			status(CodeNotFound, "link not found")
			return
		}
		out.str(1, l.LinkID)
		out.str(2, l.AccountID)
		out = append(out, 0x18, byte(l.State))
	case linksService + "ReserveLink":
		k := in.str(2) + "/" + in.str(3)
		l := f.links[k]
		if l != nil && l.AccountID != in.str(1) {
			status(10, "conflict")
			return
		}
		if l == nil || l.State == StateRevoked {
			l = &Link{LinkID: "link-" + k, AccountID: in.str(1), State: StatePending}
			f.links[k] = l
		}
		out.str(1, l.LinkID)
		out = append(out, 0x10, byte(StatePending))
	case linksService + "ActivateLink":
		for _, l := range f.links {
			if l.LinkID == in.str(1) {
				if l.State != StatePending {
					status(CodeFailedPrecond, "not pending")
					return
				}
				l.State = StateActive
			}
		}
		out = append(out, 0x08, byte(StateActive))
	case linksService + "SetLinkPublicCode":
		done := false
		for _, l := range f.links {
			if l.LinkID == in.str(1) && l.State == StateActive {
				f.codes[l.LinkID] = in.str(2)
				done = true
			}
		}
		if !done {
			status(CodeFailedPrecond, "not active")
			return
		}
	case identityService + "VerifyPassword":
		if in.str(1) != "x360" || in.str(2) != "console_login" {
			status(3, "namespace/purpose")
			return
		}
		switch {
		case in.str(3) == "ann@example.org" && in.str(4) == "pw":
			out.str(1, "A-ann")
			out = append(out, 0x10, 1)
		case in.str(3) == "bob@example.org" && in.str(4) == "pw":
			out.str(1, "A-bob")
			out = append(out, 0x10, 1)
		case in.str(3) == "banned@example.org":
			out = append(out, 0x10, 2)
		case in.str(3) == "tfa@example.org":
			status(CodeFailedPrecond, "two-factor authentication required")
			return
		default:
			status(CodeUnauthenticated, "invalid credentials")
			return
		}
	default:
		status(12, "unimplemented")
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	fr := make([]byte, 5, 5+len(out))
	binary.BigEndian.PutUint32(fr[1:], uint32(len(out)))
	w.Write(append(fr, out...))
	status(0, "")
}

func newFake(t *testing.T) (*fakeCore, *Client) {
	t.Helper()
	f := &fakeCore{links: map[string]*Link{}, codes: map[string]string{}, key: testKey}
	srv := httptest.NewUnstartedServer(f)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestGetLinkBySubject(t *testing.T) {
	f, c := newFake(t)
	f.links[ConsoleNamespace+"/000123456789"] = &Link{LinkID: "L1", AccountID: "A1", State: StateActive}
	l, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "000123456789")
	if err != nil || l.LinkID != "L1" || l.AccountID != "A1" || l.State != StateActive {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "nope"); !IsNotFound(err) {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestBadTokenAndBadURL(t *testing.T) {
	f := &fakeCore{links: map[string]*Link{}, codes: map[string]string{}, key: testKey}
	srv := httptest.NewUnstartedServer(f)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	defer srv.Close()
	c, _ := New(srv.URL, "wrong", nil)
	_, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "x")
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	if _, err := New("ftp://x", "t", nil); err == nil {
		t.Fatal("bad scheme accepted")
	}
	if _, err := New("http://x", "", nil); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestUnreachableCoreFails(t *testing.T) {
	c, _ := New("http://127.0.0.1:1", "k", nil)
	if _, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnrol(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	e := &Enroller{Core: c}
	// Never seen: unowned, accepted.
	en, err := e.Enrol(ctx, "000000000001")
	if err != nil || en.Owned() {
		t.Fatalf("%+v %v", en, err)
	}
	f.links[ConsoleNamespace+"/000000000002"] = &Link{LinkID: "L2", AccountID: "A2", State: StateActive}
	en, err = e.Enrol(ctx, "000000000002")
	if err != nil || en.LinkID != "L2" || en.AccountID != "A2" {
		t.Fatalf("%+v %v", en, err)
	}
	k := ConsoleNamespace + "/000000000003"
	f.links[k] = &Link{LinkID: "L3", AccountID: "A2", State: StatePending}
	if en, err := e.Enrol(ctx, "000000000003"); err != nil || en.Owned() {
		t.Fatalf("pending should be unowned: %+v %v", en, err)
	}
	for _, st := range []LinkState{StateRevoking, StateRevoked} {
		f.links[k].State = st
		if _, err := e.Enrol(ctx, "000000000003"); !errors.Is(err, ErrRevoked) {
			t.Fatalf("state %s accepted: %v", st, err)
		}
	}
}

func TestSignIn(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	s := &SignInService{Core: c}
	req := SignInRequest{ConsoleDigits: "000000000010", XUID: 0x0009000000001234, Gamertag: "Cool Tag", Email: "ann@example.org", Password: "pw"}

	r, err := s.SignIn(ctx, req)
	if err != nil || r.AccountID != "A-ann" {
		t.Fatalf("%+v %v", r, err)
	}
	cl := f.links[ConsoleNamespace+"/000000000010"]
	ul := f.links[UserNamespace+"/0009000000001234"]
	if cl == nil || cl.State != StateActive || cl.AccountID != "A-ann" || ul == nil || ul.State != StateActive || f.codes[ul.LinkID] != "Cool Tag" {
		t.Fatalf("links: %+v %+v %v", cl, ul, f.codes)
	}
	// Idempotent for the same person.
	if _, err := s.SignIn(ctx, req); err != nil {
		t.Fatal(err)
	}
	// Another account on a console already paired: refused, and nothing changed.
	other := req
	other.Email, other.XUID = "bob@example.org", 0x0009000000005678
	if _, err := s.SignIn(ctx, other); !errors.Is(err, ErrConsoleOwned) {
		t.Fatalf("want ErrConsoleOwned, got %v", err)
	}
	if f.links[UserNamespace+"/0009000000005678"] != nil {
		t.Fatal("profile linked despite console refusal")
	}
	// Same profile, different person, on a fresh console.
	other = req
	other.Email, other.ConsoleDigits = "bob@example.org", "000000000011"
	if _, err := s.SignIn(ctx, other); !errors.Is(err, ErrUserOwned) {
		t.Fatalf("want ErrUserOwned, got %v", err)
	}
	// A pending reservation of the same account is activated; revoked returns.
	f.links[ConsoleNamespace+"/000000000012"] = &Link{LinkID: "P", AccountID: "A-ann", State: StatePending}
	p := req
	p.ConsoleDigits = "000000000012"
	if _, err := s.SignIn(ctx, p); err != nil || f.links[ConsoleNamespace+"/000000000012"].State != StateActive {
		t.Fatalf("pending: %v", err)
	}
	// Credential failures.
	for _, em := range []string{"nobody@example.org", "banned@example.org", "tfa@example.org"} {
		bad := req
		bad.Email, bad.ConsoleDigits = em, "000000000099"
		if _, err := s.SignIn(ctx, bad); err == nil {
			t.Fatalf("%s accepted", em)
		}
	}
	if f.links[ConsoleNamespace+"/000000000099"] != nil {
		t.Fatal("link created for failed credentials")
	}
	bad := req
	bad.Password = ""
	if _, err := s.SignIn(ctx, bad); err == nil {
		t.Fatal("empty password accepted")
	}
}

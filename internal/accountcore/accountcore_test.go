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
	links map[string]*Link // by subject
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
		l := f.links[in.str(2)]
		if l == nil || in.str(1) != ConsoleNamespace {
			status(CodeNotFound, "link not found")
			return
		}
		out.str(1, l.LinkID)
		out.str(2, l.AccountID)
		out = append(out, 0x18, byte(l.State))
	case linksService + "ReserveLink":
		l := &Link{LinkID: "link-" + in.str(3), AccountID: in.str(1), State: StatePending}
		f.links[in.str(3)] = l
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
	f := &fakeCore{links: map[string]*Link{}, key: testKey}
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
	f.links["000123456789"] = &Link{LinkID: "L1", AccountID: "A1", State: StateActive}
	l, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "000123456789")
	if err != nil || l.LinkID != "L1" || l.AccountID != "A1" || l.State != StateActive {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := c.GetLinkBySubject(context.Background(), ConsoleNamespace, "nope"); !IsNotFound(err) {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestBadTokenAndBadURL(t *testing.T) {
	f := &fakeCore{links: map[string]*Link{}, key: testKey}
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
	if _, err := e.Enrol(ctx, "000000000001"); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("unknown console without enrol account: %v", err)
	}
	f.links["000000000002"] = &Link{LinkID: "L2", AccountID: "A2", State: StateActive}
	en, err := e.Enrol(ctx, "000000000002")
	if err != nil || en.LinkID != "L2" || en.AccountID != "A2" || en.Created {
		t.Fatalf("%+v %v", en, err)
	}
	for _, st := range []LinkState{StatePending, StateRevoking, StateRevoked} {
		f.links["000000000003"] = &Link{LinkID: "L3", AccountID: "A2", State: st}
		if _, err := e.Enrol(ctx, "000000000003"); !errors.Is(err, ErrNotPaired) {
			t.Fatalf("state %s accepted: %v", st, err)
		}
	}
	e.EnrolAccount = "POOL"
	en, err = e.Enrol(ctx, "000000000004")
	if err != nil || !en.Created || en.AccountID != "POOL" || f.links["000000000004"].State != StateActive {
		t.Fatalf("%+v %v", en, err)
	}
}

package kdc

import (
	"context"
	"errors"
	"testing"

	"openpak/x360-kdc/internal/accountcore"
)

type stubCore struct {
	en  *accountcore.Enrolment
	err error
	n   int
}

func (s *stubCore) Enrol(_ context.Context, digits string) (*accountcore.Enrolment, error) {
	s.n++
	return s.en, s.err
}

func TestMACSWithCore(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{0, 0, 0, 1, 2})
	name := ConsoleDigits(c.cert) + "@" + AccountDomain

	// Core refuses: no reply, nothing cached.
	core := &stubCore{err: accountcore.ErrNotPaired}
	h.Core = core
	req, _ := c.macsReq(t, &h.XMACS.PublicKey, 1, t0)
	rep, _, err := h.Handle(req)
	if err == nil || rep != nil || !errors.Is(err, accountcore.ErrNotPaired) {
		t.Fatalf("want rejection, got %v %v", rep, err)
	}
	if h.Accounts.Get(name) != nil {
		t.Fatal("rejected console was cached")
	}

	// Core unreachable: same.
	core.err = errors.New("dial tcp: connection refused")
	req, _ = c.macsReq(t, &h.XMACS.PublicKey, 2, t0)
	if rep, _, err := h.Handle(req); err == nil || rep != nil {
		t.Fatal("core outage must reject")
	}

	// Paired: reply, ids cached and logged.
	core.err, core.en = nil, &accountcore.Enrolment{LinkID: "L1", AccountID: "A1"}
	req, _ = c.macsReq(t, &h.XMACS.PublicKey, 3, t0)
	rep, res, err := h.Handle(req)
	if err != nil || rep == nil {
		t.Fatalf("paired MACS: %v", err)
	}
	a := h.Accounts.Get(name)
	if a == nil || a.CoreLinkID != "L1" || a.CoreAccountID != "A1" {
		t.Fatalf("cache: %+v", a)
	}
	found := false
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		if res.Attrs[i] == "core_link" && res.Attrs[i+1] == "L1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("core link not logged: %v", res.Attrs)
	}
}

func TestXEASRefusesUnboundAccountWhenCoreConfigured(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{0, 0, 0, 1, 3})
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, 5, t0) // no Core yet: dev-style local account
	rep, _, err := h.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	name := ConsoleDigits(c.cert) + "@" + AccountDomain
	_ = rep
	_ = secret
	key, _ := h.Accounts.Get(name).Key()
	h.Core = &stubCore{}
	_, _, err = h.Handle(xeasReq(name, key, 6, t0))
	if err == nil {
		t.Fatal("XEAS must refuse an account without a core pairing once the core is configured")
	}
	if err := h.Accounts.BindCore(name, "L", "A"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Handle(xeasReq(name, key, 7, t0)); err != nil {
		t.Fatalf("bound account refused: %v", err)
	}
}

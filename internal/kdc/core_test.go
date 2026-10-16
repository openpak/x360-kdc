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

	// Revoked in the core: no reply, nothing cached.
	core := &stubCore{err: accountcore.ErrRevoked}
	h.Core = core
	req, _ := c.macsReq(t, &h.XMACS.PublicKey, 1, t0)
	rep, _, err := h.Handle(req)
	if !errors.Is(err, accountcore.ErrRevoked) || rep != nil || h.Accounts.Get(name) != nil {
		t.Fatalf("want rejection, got %v %v", rep, err)
	}

	// Core unreachable: same.
	core.err = errors.New("dial tcp: connection refused")
	req, _ = c.macsReq(t, &h.XMACS.PublicKey, 2, t0)
	if rep, _, err := h.Handle(req); err == nil || rep != nil {
		t.Fatal("core outage must reject")
	}

	// Never seen by the core: unowned, still gets its machine account, TGT and sg/S0.
	core.err, core.en = nil, &accountcore.Enrolment{}
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, 3, t0)
	rep, _, err = h.Handle(req)
	if err != nil || rep == nil {
		t.Fatalf("unowned MACS: %v", err)
	}
	_ = secret
	a := h.Accounts.Get(name)
	if a == nil || a.CoreLinkID != "" {
		t.Fatalf("cache: %+v", a)
	}
	key, _ := a.Key()
	xrep, _, err := h.Handle(xeasReq(name, key, 4, t0))
	if err != nil {
		t.Fatalf("XEAS for unowned console: %v", err)
	}
	as := decodeRep(t, xrep, tagASRep, msgASRep, key, 4, tagEncAS)
	_ = as

	// Paired in the core: ids cached and logged.
	core.en = &accountcore.Enrolment{LinkID: "L1", AccountID: "A1"}
	req, _ = c.macsReq(t, &h.XMACS.PublicKey, 5, t0)
	_, res, err := h.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	a = h.Accounts.Get(name)
	if a.CoreLinkID != "L1" || a.CoreAccountID != "A1" {
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

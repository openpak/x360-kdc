package gateway

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"openpak/x360-kdc/internal/kdc"
)

type fakePresence struct {
	reg, hb, exp []string
	failHB       bool
}

func (f *fakePresence) RegisterSession(_ context.Context, acct, ns, title, ref string, lease int, client, os string) (string, int, error) {
	if ns != PresenceNamespace || title != "" || ref == "" {
		return "", 0, errors.New("bad register")
	}
	f.reg = append(f.reg, acct)
	return "s-" + acct, lease, nil
}
func (f *fakePresence) Heartbeat(_ context.Context, id string) error {
	f.hb = append(f.hb, id)
	if f.failHB {
		return errors.New("lapsed")
	}
	return nil
}
func (f *fakePresence) ExpireSession(_ context.Context, id string) error {
	f.exp = append(f.exp, id)
	return nil
}

func TestPresenceLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)
	g := &Gateway{Now: func() time.Time { return now }}
	src := netip.MustParseAddrPort("10.0.0.5:3074")
	g.sessions = map[netip.AddrPort]*Session{src: {Account: "478700668470@xbox.com", expires: now.Add(SessionTTL), lastSeen: now,
		Users: []kdc.TicketUser{{XUID: 0x0009000000000001, Account: "A-ann"}}}}
	core := &fakePresence{}
	p := &Presence{Gateway: g, Core: core}
	ctx := context.Background()
	p.Tick(ctx)
	if len(core.reg) != 1 || core.reg[0] != "A-ann" {
		t.Fatalf("register: %v", core.reg)
	}
	p.Tick(ctx)
	if len(core.hb) != 1 || len(core.reg) != 1 {
		t.Fatalf("heartbeat: %v %v", core.hb, core.reg)
	}
	core.failHB = true
	p.Tick(ctx)
	if len(core.reg) != 2 {
		t.Fatal("lapsed lease not re-registered")
	}
	// Console silent for longer than PresenceIdle: offline.
	now = now.Add(PresenceIdle + time.Second)
	p.Tick(ctx)
	if len(core.exp) != 1 || len(p.live) != 0 {
		t.Fatalf("expire: %v", core.exp)
	}
}

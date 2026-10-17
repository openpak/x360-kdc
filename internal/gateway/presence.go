package gateway

// Presence: a user signed in to Live on a 360 (user logon ticket in a live
// security-gateway session) is online in the OpenPak account core, namespace
// "xbox360", so every other platform's friend list shows them (nx-baas,
// nn-friends, np-account, the website all read Sessions.GetPresence). One core
// lease per (account, online XUID), registered when the user appears in a live
// session, renewed while the console keeps talking to the gateway, expired when
// no session carries the user any more or the console has been silent for
// PresenceIdle.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"openpak/x360-kdc/internal/kdc"
)

// PresenceNamespace is the core namespace of Xbox 360 presence; every
// platform's label table knows it ("Xbox 360").
const PresenceNamespace = "xbox360"

// PresenceCore is the account core's Sessions service.
type PresenceCore interface {
	RegisterSession(ctx context.Context, accountID, namespace, titleID, endpointRef string, leaseSeconds int, client, os string) (string, int, error)
	Heartbeat(ctx context.Context, sessionID string) error
	ExpireSession(ctx context.Context, sessionID string) error
}

// OnlineUser is a user in a live session.
type OnlineUser struct {
	kdc.TicketUser
	Console string // "<digits>@xbox.com"
}

// OnlineUsers lists the users of sessions that are live and heard from within idle.
func (g *Gateway) OnlineUsers(idle time.Duration) []OnlineUser {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	seen := map[uint64]bool{}
	var out []OnlineUser
	for _, s := range g.sessions {
		if now.After(s.expires) || now.Sub(s.lastSeen) > idle {
			continue
		}
		for _, u := range s.Users {
			if !seen[u.XUID] {
				seen[u.XUID] = true
				out = append(out, OnlineUser{TicketUser: u, Console: s.Account})
			}
		}
	}
	return out
}

// Presence publishes OnlineUsers to the core.
type Presence struct {
	Gateway *Gateway
	Core    PresenceCore
	Log     *slog.Logger
	Every   time.Duration // default 15 s
	Lease   int           // seconds, default 60
	Idle    time.Duration // default PresenceIdle
	Client  string        // core "client" label; empty = a real console or unknown

	live map[uint64]string // online XUID -> core session id
}

// PresenceIdle is how long a console may stay silent on the gateway before
// its users count as offline.
const PresenceIdle = 3 * time.Minute

func (p *Presence) Run(ctx context.Context) {
	every := p.Every
	if every <= 0 {
		every = 15 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		p.Tick(ctx)
		select {
		case <-ctx.Done():
			ec, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			for x, id := range p.live {
				p.Core.ExpireSession(ec, id)
				delete(p.live, x)
			}
			cancel()
			return
		case <-t.C:
		}
	}
}

// Tick registers new users, renews present ones and expires gone ones.
func (p *Presence) Tick(ctx context.Context) {
	if p.live == nil {
		p.live = map[uint64]string{}
	}
	idle := p.Idle
	if idle <= 0 {
		idle = PresenceIdle
	}
	lease := p.Lease
	if lease <= 0 {
		lease = 60
	}
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	now := map[uint64]bool{}
	for _, u := range p.Gateway.OnlineUsers(idle) {
		now[u.XUID] = true
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		if id, ok := p.live[u.XUID]; ok {
			if err := p.Core.Heartbeat(c, id); err == nil {
				cancel()
				continue
			}
			log.Info("presence lease lapsed, registering again", "xuid", fmt.Sprintf("%016x", u.XUID))
		}
		id, _, err := p.Core.RegisterSession(c, u.Account, PresenceNamespace, "", fmt.Sprintf("x360:%016x", u.XUID), lease, p.Client, "")
		cancel()
		if err != nil {
			log.Warn("presence register failed", "account", u.Account, "xuid", fmt.Sprintf("%016x", u.XUID), "err", err)
			delete(p.live, u.XUID)
			continue
		}
		if _, had := p.live[u.XUID]; !had {
			log.Info("presence online", "account", u.Account, "xuid", fmt.Sprintf("%016x", u.XUID), "console", u.Console)
		}
		p.live[u.XUID] = id
	}
	for x, id := range p.live {
		if now[x] {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := p.Core.ExpireSession(c, id)
		cancel()
		log.Info("presence offline", "xuid", fmt.Sprintf("%016x", x), "err", err)
		delete(p.live, x)
	}
}

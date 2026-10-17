package xuacs

import (
	"context"
	"time"
)

// ReconcileAll gives every active account in the core an x360 profile link,
// whether or not it ever used the network. Only the profile (online XUID) is
// projected: the console link stays a real enrolment, because a console's
// 12 digits come from its certificate and are never invented. The XUID is the
// account's own (Store.OnlineXUID: the stored one, else the derived one), and
// identity() prefers an existing x360 link's subject, so a later 0x63F
// enrolment adopts this link instead of creating another. An account that
// already has an active x360 link is left alone, and a profile held by a
// different account is skipped. One account's failure never stops the pass.
// Returns counts only (no names or emails are read).
func (h *Handler) ReconcileAll(ctx context.Context) (seen, linked, failed int, err error) {
	after := ""
	for {
		ids, next, err := h.Core.ListAccounts(ctx, after, 200)
		if err != nil {
			return seen, linked, failed, err
		}
		for _, id := range ids {
			seen++
			l, e := h.Core.ActiveXboxLink(ctx, id)
			if e != nil {
				failed++
				continue
			}
			if l != nil {
				continue
			}
			xuid, e := h.Store.OnlineXUID(id, 0)
			if e == nil {
				e = h.Core.LinkProfile(ctx, id, xuid)
			}
			if e != nil {
				failed++
				continue
			}
			linked++
		}
		if next == "" || next == after || len(ids) == 0 {
			return seen, linked, failed, nil
		}
		after = next
	}
}

// RunReconcile runs ReconcileAll at start and then every interval until ctx ends.
func (h *Handler) RunReconcile(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		seen, linked, failed, err := h.ReconcileAll(ctx)
		if err != nil {
			h.log().Error("reconcile accounts", "err", err, "seen", seen, "linked", linked, "failed", failed)
		} else {
			h.log().Info("reconcile accounts", "seen", seen, "linked", linked, "failed", failed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

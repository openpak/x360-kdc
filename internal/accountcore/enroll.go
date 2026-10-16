package accountcore

import (
	"context"
	"errors"
	"fmt"
)

// ConsoleNamespace is the adapter-link namespace of an Xbox 360 console
// (machine) identity; the subject is the console's 12 decimal digits.
const ConsoleNamespace = "x360-console"

// Enrolment is the core's record of one enrolled console.
type Enrolment struct {
	LinkID    string
	AccountID string // the OpenPak account the console is paired to
	Created   bool   // true when this call created the link
}

// Enroller resolves a console to its OpenPak pairing.
type Enroller struct {
	Core *Client
	// EnrolAccount, when set, is the OpenPak account that receives consoles
	// the core has never seen. Empty (the production default) means unknown
	// consoles are refused: the core cannot hold a device without an owner.
	EnrolAccount string
}

// ErrNotPaired is returned for a console with no active pairing.
var ErrNotPaired = errors.New("console is not paired to an OpenPak account")

// Enrol returns the active link of a console. A console the core has never
// seen is paired to EnrolAccount when configured, else ErrNotPaired. A link in
// any state but active (pending, revoking, revoked) is refused.
func (e *Enroller) Enrol(ctx context.Context, digits string) (*Enrolment, error) {
	l, err := e.Core.GetLinkBySubject(ctx, ConsoleNamespace, digits)
	switch {
	case err == nil:
		if l.State != StateActive {
			return nil, fmt.Errorf("%w: link %s is %s", ErrNotPaired, l.LinkID, l.State)
		}
		return &Enrolment{LinkID: l.LinkID, AccountID: l.AccountID}, nil
	case !IsNotFound(err):
		return nil, err
	}
	if e.EnrolAccount == "" {
		return nil, ErrNotPaired
	}
	key := "x360-kdc-enrol-" + digits
	r, err := e.Core.ReserveLink(ctx, e.EnrolAccount, ConsoleNamespace, digits, key)
	if err != nil {
		return nil, err
	}
	if _, err := e.Core.ActivateLink(ctx, r.LinkID, key); err != nil {
		return nil, err
	}
	return &Enrolment{LinkID: r.LinkID, AccountID: e.EnrolAccount, Created: true}, nil
}

package accountcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Adapter-link namespaces: a console (subject = its 12 digits) and a user
// profile (subject = the online XUID as 16 hex digits, public code = gamertag).
const (
	ConsoleNamespace = "x360-console"
	UserNamespace    = "x360"
)

// Enrolment is what the core says about one console.
type Enrolment struct {
	LinkID    string // empty while the core has no link: the console is unowned
	AccountID string // the OpenPak account the console is paired to; empty when unowned
}

// Owned reports an active pairing.
func (e *Enrolment) Owned() bool { return e.LinkID != "" }

// Errors callers can test with errors.Is.
var (
	ErrRevoked       = errors.New("console pairing was revoked in the account core")
	ErrConsoleOwned  = errors.New("console is already paired to another OpenPak account")
	ErrUserOwned     = errors.New("profile is already linked to another OpenPak account")
	ErrBadCredential = errors.New("invalid OpenPak credentials")
)

// Enroller answers the KDC's machine-level questions.
type Enroller struct{ Core *Client }

// Enrol looks a console up. A console the core has never seen, or whose
// reservation is still pending, is unowned and accepted (the core cannot hold
// a device without an owner; the KDC keeps it locally until a person signs in
// on it). Revoking and revoked links are refused. Core errors are returned.
func (e *Enroller) Enrol(ctx context.Context, digits string) (*Enrolment, error) {
	l, err := e.Core.GetLinkBySubject(ctx, ConsoleNamespace, digits)
	switch {
	case IsNotFound(err):
		return &Enrolment{}, nil
	case err != nil:
		return nil, err
	}
	switch l.State {
	case StateActive:
		return &Enrolment{LinkID: l.LinkID, AccountID: l.AccountID}, nil
	case StatePending:
		return &Enrolment{}, nil
	}
	return nil, fmt.Errorf("%w: link %s is %s", ErrRevoked, l.LinkID, l.State)
}

// SignIn is the outcome of a verified user sign-in.
type SignIn struct {
	AccountID     string
	ConsoleLinkID string
	UserLinkID    string
}

// SignInRequest is a user's sign-in on a console. The credential carrier in
// the firmware's request is not captured yet (see tgs.go), so nothing builds
// this from wire bytes today.
type SignInRequest struct {
	ConsoleDigits string // 12 digits
	XUID          uint64 // online XUID
	Gamertag      string
	Email         string // OpenPak sign-in
	Password      string
}

// SignInService enrols on user sign-in: it verifies the credentials against
// the core, pairs the console to that account and links the XUID profile.
type SignInService struct{ Core *Client }

// SignIn verifies the credentials (Identity.VerifyPassword; two-factor
// accounts fail closed), then claims the console and the profile for the
// account. A console or profile held by another active account is refused.
func (s *SignInService) SignIn(ctx context.Context, r SignInRequest) (*SignIn, error) {
	if r.ConsoleDigits == "" || r.XUID == 0 || r.Email == "" || r.Password == "" {
		return nil, errors.New("sign-in: console, xuid, email and password are required")
	}
	acct, st, err := s.Core.VerifyPassword(ctx, r.Email, r.Password)
	var ce *Error
	if errors.As(err, &ce) && ce.Code == CodeUnauthenticated {
		return nil, ErrBadCredential
	}
	if err != nil {
		return nil, err
	}
	if acct == "" || st != StatusActive {
		return nil, fmt.Errorf("%w: account not active", ErrBadCredential)
	}
	return s.Link(ctx, acct, r)
}

// Link is SignIn after the credentials were verified elsewhere (the caller
// holds the verified account id): it claims the console and the profile for
// the account and publishes the gamertag. Email and Password are not used.
func (s *SignInService) Link(ctx context.Context, acct string, r SignInRequest) (*SignIn, error) {
	if acct == "" || r.ConsoleDigits == "" || r.XUID == 0 {
		return nil, errors.New("link: account, console and xuid are required")
	}
	cl, err := s.claim(ctx, acct, ConsoleNamespace, r.ConsoleDigits, ErrConsoleOwned)
	if err != nil {
		return nil, fmt.Errorf("console link: %w", err)
	}
	subject := fmt.Sprintf("%016x", r.XUID)
	ul, err := s.claim(ctx, acct, UserNamespace, subject, ErrUserOwned)
	if err != nil {
		return nil, fmt.Errorf("profile link: %w", err)
	}
	if r.Gamertag != "" {
		key := strings.ToLower(strings.Join(strings.Fields(r.Gamertag), ""))
		if err := s.Core.SetLinkPublicCode(ctx, ul, r.Gamertag, key); err != nil {
			return nil, fmt.Errorf("gamertag: %w", err)
		}
	}
	return &SignIn{AccountID: acct, ConsoleLinkID: cl, UserLinkID: ul}, nil
}

// claim makes (namespace, subject) an active link of account and returns its
// id. Idempotent for the same account; another account's active or pending
// claim returns owned.
func (s *SignInService) claim(ctx context.Context, account, ns, subject string, owned error) (string, error) {
	l, err := s.Core.GetLinkBySubject(ctx, ns, subject)
	switch {
	case IsNotFound(err):
	case err != nil:
		return "", err
	case l.AccountID != account:
		return "", owned
	case l.State == StateActive:
		return l.LinkID, nil
	}
	// Unknown, pending, or revoked (same account): reserve is idempotent and
	// returns a revoked link of the same owner to pending.
	key := "x360-kdc-" + ns + "-" + subject
	r, err := s.Core.ReserveLink(ctx, account, ns, subject, key)
	if err != nil {
		return "", err
	}
	if _, err := s.Core.ActivateLink(ctx, r.LinkID, key); err != nil {
		return "", err
	}
	return r.LinkID, nil
}

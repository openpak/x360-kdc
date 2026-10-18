// Package accountcore is a stdlib-only client for the OpenPak account core's
// Links service (openpak.account.v1.Links).
//
// The core's service API is gRPC (HTTP/2, protobuf), authenticated with the
// shared internal key in the x-internal-key header; the core has no JSON
// service API (its HTTP side is the web sign-in for people). This client
// speaks the gRPC wire format directly over net/http so the module keeps zero
// dependencies: the five-byte message frame, application/grpc, and the
// grpc-status trailer. Only the handful of messages the KDC needs are encoded.
package accountcore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	linksService    = "/openpak.account.v1.Links/"
	identityService = "/openpak.account.v1.Identity/"
)

// LinkState mirrors openpak.account.v1.LinkState.
type LinkState int

const (
	StateUnspecified LinkState = 0
	StatePending     LinkState = 1
	StateActive      LinkState = 2
	StateRevoking    LinkState = 3
	StateRevoked     LinkState = 4
)

func (s LinkState) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateActive:
		return "active"
	case StateRevoking:
		return "revoking"
	case StateRevoked:
		return "revoked"
	}
	return "unspecified"
}

// Link is the core's answer for one (namespace, subject).
type Link struct {
	LinkID     string
	AccountID  string
	State      LinkState
	SubjectID  string
	PublicCode string
}

// gRPC status codes the callers care about.
const (
	CodeNotFound        = 5
	CodeAlreadyExists   = 6
	CodeFailedPrecond   = 9
	CodeUnauthenticated = 16
)

// Error is a non-OK gRPC status.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("account core: grpc status %d: %s", e.Code, e.Message)
}

// IsNotFound reports a gRPC NotFound.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == CodeNotFound
}

// Client talks to one account core. Zero timeout means 5 seconds per call.
type Client struct {
	base    string
	token   string
	http    *http.Client
	Timeout time.Duration
}

// New builds a client. baseURL is the core's gRPC listener: http://host:7000
// (cleartext HTTP/2, as the other OpenPak adapters dial it on the private
// network) or https://host:7000. token is the internal key. hc may be nil.
func New(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("account core URL must be http(s)://host:port, got %q", baseURL)
	}
	if token == "" {
		return nil, errors.New("account core token is required")
	}
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP2(true)
		tr.Protocols.SetUnencryptedHTTP2(true)
		hc = &http.Client{Transport: tr}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: hc}, nil
}

// GetLinkBySubject looks up the link for a namespace/subject in any state.
// A subject the core has never seen is an *Error with CodeNotFound.
func (c *Client) GetLinkBySubject(ctx context.Context, namespace, subject string) (*Link, error) {
	var req pb
	req.str(1, namespace)
	req.str(2, subject)
	resp, err := c.call(ctx, linksService+"GetLinkBySubject", req)
	if err != nil {
		return nil, err
	}
	return parseLink(resp), nil
}

// ReserveLink claims subject for accountID in namespace (state pending).
func (c *Client) ReserveLink(ctx context.Context, accountID, namespace, subject, idemKey string) (*Link, error) {
	var req pb
	req.str(1, accountID)
	req.str(2, namespace)
	req.str(3, subject)
	req.str(4, idemKey)
	resp, err := c.call(ctx, linksService+"ReserveLink", req)
	if err != nil {
		return nil, err
	}
	f := parseFields(resp)
	return &Link{LinkID: f.str(1), AccountID: accountID, SubjectID: subject, State: LinkState(f.num(2))}, nil
}

// SetLinkPublicCode publishes the human code (the gamertag) on an active link.
// lookupKey is optional; empty means the display form reduced by the core.
func (c *Client) SetLinkPublicCode(ctx context.Context, linkID, code, lookupKey string) error {
	var req pb
	req.str(1, linkID)
	req.str(2, code)
	req.str(3, lookupKey)
	_, err := c.call(ctx, linksService+"SetLinkPublicCode", req)
	return err
}

// Account statuses (openpak.account.v1.AccountStatus).
const StatusActive = 1

// VerifyPassword checks an OpenPak email and password for the x360 adapter
// (purpose "console_login"). It does not offer a second-factor step: the core
// then answers FailedPrecondition for two-factor accounts (fails closed), a
// console has no field for the code. Wrong credentials are CodeUnauthenticated.
// A banned or deleted account comes back with a non-active status and no id.
func (c *Client) VerifyPassword(ctx context.Context, email, password string) (accountID string, status int, err error) {
	var req pb
	req.str(1, "x360")
	req.str(2, "console_login")
	req.str(3, email)
	req.str(4, password)
	resp, err := c.call(ctx, identityService+"VerifyPassword", req)
	if err != nil {
		return "", 0, err
	}
	f := parseFields(resp)
	return f.str(1), int(f.num(2)), nil
}

// ActivateLink promotes a pending reservation to active.
func (c *Client) ActivateLink(ctx context.Context, linkID, idemKey string) (LinkState, error) {
	var req pb
	req.str(1, linkID)
	req.str(2, idemKey)
	resp, err := c.call(ctx, linksService+"ActivateLink", req)
	if err != nil {
		return 0, err
	}
	return LinkState(parseFields(resp).num(1)), nil
}

// GetActiveLinkByAccount resolves the active link of an account in one
// namespace (CodeNotFound when there is none).
func (c *Client) GetActiveLinkByAccount(ctx context.Context, namespace, accountID string) (*Link, error) {
	var req pb
	req.str(1, namespace)
	req.str(2, accountID)
	resp, err := c.call(ctx, linksService+"GetActiveLinkByAccount", req)
	if err != nil {
		return nil, err
	}
	return parseLink(resp), nil
}

func parseLink(b []byte) *Link {
	f := parseFields(b)
	return &Link{LinkID: f.str(1), AccountID: f.str(2), State: LinkState(f.num(3)), SubjectID: f.str(4), PublicCode: f.str(5)}
}

func (c *Client) call(ctx context.Context, method string, req pb) ([]byte, error) {
	d := c.Timeout
	if d == 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	frame := make([]byte, 5, 5+len(req))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(req)))
	frame = append(frame, req...)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+method, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("TE", "trailers")
	hr.Header.Set("X-Internal-Key", c.token)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("account core: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("account core: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("account core: http status %d", resp.StatusCode)
	}
	// Trailers-only responses carry grpc-status in the headers.
	st := resp.Trailer.Get("Grpc-Status")
	msg := resp.Trailer.Get("Grpc-Message")
	if st == "" {
		st, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if st == "" {
		return nil, errors.New("account core: response without grpc-status")
	}
	code, err := strconv.Atoi(st)
	if err != nil {
		return nil, errors.New("account core: bad grpc-status")
	}
	if code != 0 {
		return nil, &Error{Code: code, Message: msg}
	}
	if len(body) < 5 || body[0] != 0 {
		return nil, errors.New("account core: bad message frame")
	}
	n := binary.BigEndian.Uint32(body[1:5])
	if int(n) != len(body)-5 {
		return nil, errors.New("account core: bad message length")
	}
	return body[5:], nil
}

// pb is a protobuf message under construction (strings only: all the request
// fields here are strings).
type pb []byte

func (p *pb) str(field int, s string) {
	if s == "" {
		return
	}
	*p = binary.AppendUvarint(*p, uint64(field)<<3|2)
	*p = binary.AppendUvarint(*p, uint64(len(s)))
	*p = append(*p, s...)
}

type fields struct {
	s map[int]string
	n map[int]uint64
}

func (f fields) str(i int) string { return f.s[i] }
func (f fields) num(i int) uint64 { return f.n[i] }

// parseFields reads the string (wire type 2) and varint (0) fields of a
// message and skips anything else; a malformed tail stops the parse.
func parseFields(b []byte) fields {
	f := fields{s: map[int]string{}, n: map[int]uint64{}}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		field := int(tag >> 3)
		switch tag & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return f
			}
			f.n[field] = v
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return f
			}
			f.s[field] = string(b[n : n+int(l)])
			b = b[n+int(l):]
		case 1:
			if len(b) < 8 {
				return f
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return f
			}
			b = b[4:]
		default:
			return f
		}
	}
	return f
}

// ListAccounts returns one page of active account ids from Identity.ListAccounts
// (keyset cursor: pass the previous next as after; next is empty at the end).
// limit is capped by the core at 500.
func (c *Client) ListAccounts(ctx context.Context, after string, limit int) (ids []string, next string, err error) {
	var req pb
	req.str(1, after)
	if limit > 0 {
		req = binary.AppendUvarint(req, 2<<3)
		req = binary.AppendUvarint(req, uint64(limit))
	}
	resp, err := c.call(ctx, identityService+"ListAccounts", req)
	if err != nil {
		return nil, "", err
	}
	for b := resp; len(b) > 0; {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		if tag&7 != 2 {
			break // the response holds only length-delimited fields
		}
		l, n := binary.Uvarint(b)
		if n <= 0 || uint64(len(b)-n) < l {
			break
		}
		body := b[n : n+int(l)]
		b = b[n+int(l):]
		switch tag >> 3 {
		case 1:
			if id := parseFields(body).str(1); id != "" {
				ids = append(ids, id)
			}
		case 2:
			next = string(body)
		}
	}
	return ids, next, nil
}

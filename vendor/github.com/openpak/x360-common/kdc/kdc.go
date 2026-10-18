// Package kdc answers the Xbox 360 firmware's three Kerberos exchanges on UDP
// port 88: the MACS console authentication (realm MACS.XBOX.COM, padata 0xDB),
// the XEAS machine-account AS exchange (realm XBOX.COM, padata 0xD8) and the
// XETGS TGS-REQ for the security gateway sg/S0 (padata 0xD6, reply 0xD7).
//
// Every byte layout and every check mirrors OpenPak's clean-room oracle derived
// from the 17559 XAM image (docs/xbox360/wharf-base-plan.md, the three dated
// MACS/XEAS/XETGS sections). Nothing here is taken from Microsoft's service.
// A request that fails any check gets no reply at all; the firmware times out
// and retries, exactly as it did against the oracle.
package kdc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/openpak/x360-common/accountcore"
	"github.com/openpak/x360-common/der"
)

// Realms and names the firmware uses. The account realm is the MACS realm
// without its prefix; the lower-case domain is the account name suffix.
const (
	MACSRealm     = "MACS.XBOX.COM"
	AccountRealm  = "XBOX.COM"
	AccountDomain = "xbox.com"
	Krbtgt        = "krbtgt"
)

// Kerberos message tags and types.
const (
	tagASReq  = 0x6a // [APPLICATION 10]
	tagASRep  = 0x6b // [APPLICATION 11]
	tagTGSReq = 0x6c // [APPLICATION 12]
	tagTGSRep = 0x6d // [APPLICATION 13]
	tagAPReq  = 0x6e // [APPLICATION 14]
	tagTicket = 0x61 // [APPLICATION 1]
	tagAuth   = 0x62 // [APPLICATION 2]
	tagEncTkt = 0x63 // [APPLICATION 3]
	tagEncAS  = 0x79 // [APPLICATION 25]
	tagEncTGS = 0x7a // [APPLICATION 26]

	pvno       = 5
	msgASReq   = 10
	msgASRep   = 11
	msgTGSReq  = 12
	msgTGSRep  = 13
	msgAPReq   = 14
	etypeRC4   = 23
	cksumMD5   = 7 // rsa-md5 checksum type in the authenticator
	nameTypeSI = 2 // NT-SRV-INST, the oracle uses it for every principal it emits
)

// Padata types. The firmware's own numbers.
const (
	PaAPReq  = 1
	PaEncTS  = 2
	PaCB     = 0xcb // 203: issued account record (MACS reply)
	PaCE     = 0xce // 206: HMAC-SHA1 + version/title text
	PaD6     = 0xd6 // 214: TGS request record
	PaD7     = 0xd7 // 215: TGS service record (reply)
	PaD8     = 0xd8 // 216: 20-byte kernel block SHA1 (XEAS)
	PaDB     = 0xdb // 219: console RSA/certificate block (MACS)
	TicketTL = time.Hour
	// Freshness is the window the oracle applies to the XEAS timestamp and the
	// TGS authenticator; MACS has no freshness check (the oracle does none).
	Freshness = 5 * time.Minute
)

// Kind names the exchange a datagram belonged to, for logs.
type Kind string

const (
	KindMACS       Kind = "MACS"
	KindXEAS       Kind = "XEAS"
	KindTGS        Kind = "TGS"
	KindUserAS     Kind = "USER-AS"
	KindRecordOnly Kind = "record-only"
)

// Result describes what Handle did, for the caller's log line. Attrs never
// contain key material.
type Result struct {
	Kind  Kind
	Attrs []any
}

// Handler holds the server's keys and policy. It is safe for one goroutine.
type Handler struct {
	XMACS    *rsa.PrivateKey // decrypts the OAEP block of padata 0xDB
	CA       *rsa.PublicKey  // OpenPak console CA, the only trust anchor
	Accounts *Store
	// Core, when set, consults the OpenPak account core at MACS: a revoked
	// pairing is refused, an active one is cached with its account, a console
	// the core has never seen stays unowned in the local store. Nil means the
	// local store alone decides (dev only).
	Core ConsoleEnroller
	// Users, when set, is the enrol-on-sign-in service for the user TGS path
	// (see tgs.go). Nil refuses user TGS requests.
	Users UserSignIn
	// Directory, when set, serves the user AS exchange (user.go): profile
	// keys and WLID ticket checks from x360-xuacs. Nil refuses user AS-REQs.
	Directory UserDirectory
	TicketKey []byte // 16 bytes, encrypts our own tickets (usage 2)
	SGAddress netip.Addr
	Now       func() time.Time // injectable clock; time.Now in production
	Log       *slog.Logger
}

// ConsoleEnroller resolves a console (12 digits) to its OpenPak pairing.
type ConsoleEnroller interface {
	Enrol(ctx context.Context, digits string) (*accountcore.Enrolment, error)
}

// UserSignIn verifies a person against the account core and claims the console
// and profile for them (accountcore.SignInService).
type UserSignIn interface {
	SignIn(ctx context.Context, r accountcore.SignInRequest) (*accountcore.SignIn, error)
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Handle processes one datagram. A nil reply with a nil error means the
// datagram was recorded but not answered; an error means rejection, also
// without a reply.
func (h *Handler) Handle(data []byte) ([]byte, *Result, error) {
	if len(data) == 0 {
		return nil, &Result{Kind: KindRecordOnly, Attrs: []any{"reason", "empty"}}, nil
	}
	switch data[0] {
	case tagASReq:
		return h.handleAS(data)
	case tagTGSReq:
		return h.handleTGS(data)
	}
	return nil, &Result{Kind: KindRecordOnly, Attrs: []any{"tag", fmt.Sprintf("%#x", data[0])}}, nil
}

// kdcReq is the decoded outer KDC-REQ: header fields, padata by type and the
// request body (its raw DER is what the TGS authenticator checksums).
type kdcReq struct {
	fields  map[int]der.TLV
	padata  map[int][]byte
	body    map[int]der.TLV
	bodyRaw []byte
	realm   string
	nonce   uint32
	sname   []string
}

// parseKDCReq decodes [APPLICATION n] SEQUENCE { [1] pvno, [2] msg-type,
// [3] padata, [4] req-body } and checks the version and message type.
func parseKDCReq(data []byte, wantTag byte, wantType uint64) (*kdcReq, error) {
	outer, err := der.One(data)
	if err != nil {
		return nil, err
	}
	if outer.Tag != wantTag {
		return nil, fmt.Errorf("application tag %#x", outer.Tag)
	}
	seq, err := der.One(outer.Value)
	if err != nil || seq.Tag != der.TagSequence {
		return nil, errors.New("KDC-REQ is not a sequence")
	}
	f, err := der.Fields(seq.Value)
	if err != nil {
		return nil, fmt.Errorf("KDC-REQ fields: %w", err)
	}
	if v, err := uintField(f, 1); err != nil || v != pvno {
		return nil, errors.New("pvno")
	}
	if v, err := uintField(f, 2); err != nil || v != wantType {
		return nil, errors.New("msg-type")
	}
	r := &kdcReq{fields: f, padata: map[int][]byte{}}
	pa, ok := f[3]
	if !ok || pa.Tag != der.TagSequence {
		return nil, errors.New("padata missing")
	}
	items, err := der.Parse(pa.Value)
	if err != nil {
		return nil, fmt.Errorf("padata: %w", err)
	}
	for _, it := range items {
		if it.Tag != der.TagSequence {
			return nil, errors.New("padata item is not a sequence")
		}
		q, err := der.Fields(it.Value)
		if err != nil {
			return nil, fmt.Errorf("padata item: %w", err)
		}
		typ, err := uintField(q, 1)
		if err != nil {
			return nil, errors.New("padata type")
		}
		val, ok := q[2]
		if !ok || val.Tag != der.TagOctetString {
			return nil, errors.New("padata value")
		}
		if _, dup := r.padata[int(typ)]; dup {
			return nil, errors.New("duplicate padata")
		}
		r.padata[int(typ)] = val.Value
	}
	body, ok := f[4]
	if !ok || body.Tag != der.TagSequence {
		return nil, errors.New("req-body missing")
	}
	r.bodyRaw = body.Raw
	if r.body, err = der.Fields(body.Value); err != nil {
		return nil, fmt.Errorf("req-body: %w", err)
	}
	realm, ok := r.body[2]
	if !ok || realm.Tag != der.TagGeneralString {
		return nil, errors.New("realm")
	}
	r.realm = string(realm.Value)
	nonce, ok := r.body[7]
	if !ok || nonce.Tag != der.TagInteger {
		return nil, errors.New("nonce")
	}
	n, err := der.Uint(nonce.Value)
	if err != nil || n > 0xffffffff {
		return nil, errors.New("nonce is not 32-bit")
	}
	r.nonce = uint32(n)
	sn, ok := r.body[3]
	if !ok {
		return nil, errors.New("sname missing")
	}
	if r.sname, err = principal(sn); err != nil {
		return nil, fmt.Errorf("sname: %w", err)
	}
	return r, nil
}

// padataTypes reports whether the request carries exactly the given set.
func (r *kdcReq) padataTypes(want ...int) bool {
	if len(r.padata) != len(want) {
		return false
	}
	for _, t := range want {
		if _, ok := r.padata[t]; !ok {
			return false
		}
	}
	return true
}

func uintField(f map[int]der.TLV, n int) (uint64, error) {
	v, ok := f[n]
	if !ok || v.Tag != der.TagInteger {
		return 0, fmt.Errorf("field [%d] missing or not an integer", n)
	}
	return der.Uint(v.Value)
}

// principal decodes PrincipalName { [0] name-type, [1] SEQUENCE OF GeneralString }
// into its string components. The name-type is not checked, like the oracle.
func principal(v der.TLV) ([]string, error) {
	if v.Tag != der.TagSequence {
		return nil, errors.New("principal is not a sequence")
	}
	f, err := der.Fields(v.Value)
	if err != nil {
		return nil, err
	}
	names, ok := f[1]
	if !ok || names.Tag != der.TagSequence {
		return nil, errors.New("principal name-string")
	}
	parts, err := der.Parse(names.Value)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Tag != der.TagGeneralString {
			return nil, errors.New("principal component is not a GeneralString")
		}
		out = append(out, string(p.Value))
	}
	return out, nil
}

// encryptedData decodes EncryptedData { [0] etype, [1] kvno OPTIONAL, [2] cipher }
// and requires etype 23.
func encryptedData(b []byte) ([]byte, error) {
	seq, err := der.One(b)
	if err != nil || seq.Tag != der.TagSequence {
		return nil, errors.New("EncryptedData is not a sequence")
	}
	f, err := der.Fields(seq.Value)
	if err != nil {
		return nil, err
	}
	if et, err := uintField(f, 0); err != nil || et != etypeRC4 {
		return nil, errors.New("etype is not 23")
	}
	c, ok := f[2]
	if !ok || c.Tag != der.TagOctetString {
		return nil, errors.New("EncryptedData cipher")
	}
	return c.Value, nil
}

// appSeqFields decodes [APPLICATION n] SEQUENCE { context fields } and
// returns the fields, checking the application tag.
func appSeqFields(b []byte, tag byte) (map[int]der.TLV, error) {
	outer, err := der.One(b)
	if err != nil {
		return nil, err
	}
	if outer.Tag != tag {
		return nil, fmt.Errorf("application tag %#x, want %#x", outer.Tag, tag)
	}
	seq, err := der.One(outer.Value)
	if err != nil || seq.Tag != der.TagSequence {
		return nil, errors.New("not a sequence")
	}
	return der.Fields(seq.Value)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Package xuacs serves the Xbox 360 account service (Live service 5, "xuacs"):
// the XRL requests the Guide.AccountRecovery applet ("Download Profile") sends
// to /xuacs/*.ashx through the security gateway's TCP transport.
//
// Wire format (clean-room notes signin-download-profile.md sections 4-6 and
// xon-hive-format.md): POST, Content-Type "xon/5", X-Schema-Ver 6.5, bodies
// little-endian, strings "u16 len | bytes". ENVELOPE DECISION: the engine adds
// no envelope of its own; the "u32 total | u16 chunks | {u16 len, bytes}"
// layout of GetLiveConfig is that one response schema's own fields, so xuacs
// replies are the raw fields listed in the schema table, nothing around them.
// If a live capture proves otherwise, only the reply helper (respond) changes.
//
// Items marked [guess] are not established by the notes.
package xuacs

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"openpak/x360-kdc/internal/accountcore"
	"openpak/x360-kdc/internal/gateway"
)

// Paths of the endpoints (matched case-insensitively).
const (
	PathMemberExists = "/xuacs/PassportMemberNameExists.ashx"              // 0x645
	PathProxyParams  = "/xuacs/XePassportGetEncryptedProxyParameters.ashx" // 0x64A (= 0x606)
	PathLogin        = "/xuacs/XePassportLogin.ashx"                       // 0x608
	PathGamertag     = "/xuacs/XeGetLinkedGamertag.ashx"                   // 0x60E
	PathUserType     = "/xuacs/XeGetUserType.ashx"                         // 0x624
	PathFamily       = "/xuacs/EnumFamilyMembers.ashx"                     // 0x1707
	PathAccountInfo  = "/xuacs/XeGetAccountInfoFromPassport.ashx"          // 0x627
	PathRecover      = "/xuacs/RecoverAccount.ashx"                        // 0x63F, 0x649
)

const (
	// ContentType of replies; the request carries xon/<service id in hex>.
	ContentType = "xon/5"

	Domain = "xbox.com" // account domain in the 0x63F reply
	Realm  = "XBOX.COM" // and its realm

	userTypeXenon = 2
	recoverLen    = 8 + 28 + 8 + 1 // 0x63F request: machineId, token, online XUID, isDependent

	proxyBlobLen = 32
	proxyTTL     = 15 * time.Minute
	maxBody      = 8192
)

// DefaultMaxSkew is the allowed difference between the console's timestamp in
// the password blob and our clock.
const DefaultMaxSkew = 5 * time.Minute

// Core is what xuacs needs from the OpenPak account core.
type Core interface {
	// VerifyPassword returns the account id and status (accountcore.StatusActive).
	VerifyPassword(ctx context.Context, email, password string) (account string, status int, err error)
	// ActiveXboxLink returns the account's active x360 profile link, or nil.
	ActiveXboxLink(ctx context.Context, account string) (*accountcore.Link, error)
	// Enrol links the console and the profile to the account.
	Enrol(ctx context.Context, account string, r accountcore.SignInRequest) error
	// ListAccounts returns one page of active account ids (keyset cursor).
	ListAccounts(ctx context.Context, after string, limit int) (ids []string, next string, err error)
	// LinkProfile claims the account's x360 profile link without a console.
	LinkProfile(ctx context.Context, account string, xuid uint64) error
}

// CoreClient adapts the account core client to Core.
type CoreClient struct {
	Client *accountcore.Client
}

func (c CoreClient) VerifyPassword(ctx context.Context, email, pw string) (string, int, error) {
	return c.Client.VerifyPassword(ctx, email, pw)
}

func (c CoreClient) ActiveXboxLink(ctx context.Context, account string) (*accountcore.Link, error) {
	l, err := c.Client.GetActiveLinkByAccount(ctx, accountcore.UserNamespace, account)
	if accountcore.IsNotFound(err) {
		return nil, nil
	}
	return l, err
}

func (c CoreClient) Enrol(ctx context.Context, account string, r accountcore.SignInRequest) error {
	_, err := (&accountcore.SignInService{Core: c.Client}).Link(ctx, account, r)
	return err
}

func (c CoreClient) ListAccounts(ctx context.Context, after string, limit int) ([]string, string, error) {
	return c.Client.ListAccounts(ctx, after, limit)
}

func (c CoreClient) LinkProfile(ctx context.Context, account string, xuid uint64) error {
	_, err := (&accountcore.SignInService{Core: c.Client}).LinkProfile(ctx, account, xuid)
	return err
}

// Handler serves the /xuacs endpoints.
type Handler struct {
	Core    Core
	Key     *rsa.PrivateKey // RSA-2048, advertised by 0x64A, unwraps the 0x608 session key
	Store   *Store
	Log     *slog.Logger
	Now     func() time.Time // default time.Now
	MaxSkew time.Duration    // default DefaultMaxSkew
	// WLIDKey signs the Windows Live ID access and refresh tokens (wlid.go).
	WLIDKey []byte
	// TrustLeaf decides /xsig/ValidateCertificate.ashx (xsig.go); nil trusts nothing.
	TrustLeaf func(der []byte) bool

	mu    sync.Mutex
	proxy map[string]time.Time // issued proxy blobs (hex) -> expiry
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// reqErr is an HTTP error reply.
type reqErr struct {
	status int
	msg    string
}

func (e *reqErr) Error() string { return e.msg }

func bad(msg string, a ...any) *reqErr    { return &reqErr{http.StatusBadRequest, fmt.Sprintf(msg, a...)} }
func deny(status int, msg string) *reqErr { return &reqErr{status, msg} }

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw, status: http.StatusOK}
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	log := h.log()
	shown := body
	if len(shown) > 64 {
		shown = nil // bodies above 64 bytes carry key material and credentials: length only
	}
	log.Info("request", "method", r.Method, "path", r.URL.Path, "user_agent", r.Header.Get("User-Agent"),
		"content_type", r.Header.Get("Content-Type"), "x_schema_ver", r.Header.Get("X-Schema-Ver"),
		"account", r.Header.Get(gateway.AccountHeader), "body_len", len(body), "body_hex", hex.EncodeToString(shown),
		"remote", r.RemoteAddr)

	if strings.EqualFold(r.URL.Path, PathValidateCert) {
		out := h.validateCert(body)
		w.Header().Set("Content-Type", "xon/c")
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		w.WriteHeader(http.StatusOK)
		w.Write(out)
		log.Info("response", "path", r.URL.Path, "status", w.status, "body_hex", hex.EncodeToString(out))
		return
	}
	if id, ok := countryInfoID(r.URL.Path); ok {
		h.serveCountryInfo(w, r, id)
		log.Info("response", "path", r.URL.Path, "status", w.status)
		return
	}

	if h.xpresence(w, r, body) || h.revocation(w, r, body) {
		return
	}

	var out []byte
	var err error
	switch strings.ToLower(r.URL.Path) {
	case strings.ToLower(PathMemberExists):
		out, err = h.memberExists(body)
	case strings.ToLower(PathProxyParams):
		out, err = h.proxyParams()
	case strings.ToLower(PathLogin):
		out, err = h.login(r.Context(), body)
	case strings.ToLower(PathGamertag):
		out, err = h.gamertag(r.Context(), body)
	case strings.ToLower(PathUserType):
		out, err = h.userType(body)
	case strings.ToLower(PathFamily):
		out, err = h.family(body)
	case strings.ToLower(PathAccountInfo):
		out, err = h.accountInfo(r.Context(), body)
	case strings.ToLower(PathRecover):
		out, err = h.recover(r.Context(), body, r.Header.Get(gateway.AccountHeader))
	default:
		http.NotFound(w, r)
		log.Info("response", "path", r.URL.Path, "status", w.status)
		return
	}
	if err != nil {
		var re *reqErr
		if !errors.As(err, &re) {
			log.Error("internal", "path", r.URL.Path, "err", err)
			re = &reqErr{http.StatusInternalServerError, "internal error"}
		}
		log.Info("refused", "path", r.URL.Path, "reason", re.msg)
		http.Error(w, re.msg, re.status)
		log.Info("response", "path", r.URL.Path, "status", w.status)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	log.Info("response", "path", r.URL.Path, "status", w.status, "body_len", len(out))
	if len(out) <= 64 {
		log.Debug("response body", "hex", hex.EncodeToString(out))
	}
}

// ---- wire helpers ----

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || len(r.b) < n {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.LittleEndian.Uint16(v))
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}

func (r *reader) lv() []byte { return r.take(r.u16()) } // u16 len | bytes

// str appends "u16 len+1 | bytes | NUL" (UTF-8 strings count their NUL).
func str(b []byte, s string) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

func cstr(b []byte) string { return strings.TrimRight(string(b), "\x00") }

// ---- 0x645 ----

// memberExists answers 0x645. [guess] The account core's client offers no
// lookup by email (only Identity.VerifyPassword), so the answer is always
// "exists" (01): the applet then asks for the password and a wrong email fails
// at 0x608 with the same error as a wrong password, which also avoids an
// account-enumeration oracle. Revisit when the core exposes an email lookup.
func (h *Handler) memberExists(body []byte) ([]byte, error) {
	r := &reader{b: body}
	l := r.u16()
	email := cstr(r.take(l))
	if r.bad || l == 0 || l > 113 || email == "" {
		return nil, bad("0x645: malformed request (%d bytes)", len(body))
	}
	h.log().Debug("member name exists", "email", email)
	return []byte{1}, nil
}

// ---- 0x64A ----

// proxyParams answers 0x64A (and 0x606): a random 32-byte proxy blob that we
// record, the RSA public exponent and the 256-byte big-endian modulus.
// [guess] the trailing 20 bytes (unused by the applet) are SHA-1 of the modulus.
func (h *Handler) proxyParams() ([]byte, error) {
	blob := make([]byte, proxyBlobLen)
	if _, err := rand.Read(blob); err != nil {
		return nil, err
	}
	now := h.now()
	h.mu.Lock()
	if h.proxy == nil {
		h.proxy = map[string]time.Time{}
	}
	for k, t := range h.proxy {
		if now.After(t) {
			delete(h.proxy, k)
		}
	}
	h.proxy[hex.EncodeToString(blob)] = now.Add(proxyTTL)
	h.mu.Unlock()

	// The applet feeds the wire modulus to XeCryptBnQwNeRsaPubCrypt after one
	// per-qword swap, so the key must travel as a little-endian integer (least
	// significant byte first). Big-endian made the client see an even modulus
	// and fail before sending 0x608 (dialog "problem with the credentials", 0).
	mod := reverseBytes(h.Key.N.FillBytes(make([]byte, 256)))
	dg := sha1.Sum(mod)
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(blob)))
	out = append(out, blob...)
	out = binary.LittleEndian.AppendUint32(out, uint32(h.Key.E))
	out = binary.LittleEndian.AppendUint16(out, 256)
	out = append(out, mod...)
	return append(out, dg[:]...), nil
}

func (h *Handler) proxyKnown(blob []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.proxy[hex.EncodeToString(blob)]
	return ok && !h.now().After(t)
}

// ---- 0x608 ----

func des3CBC(key, data []byte, decrypt bool) ([]byte, error) {
	blk, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%des.BlockSize != 0 {
		return nil, errors.New("3des: bad length")
	}
	iv := make([]byte, des.BlockSize)
	out := make([]byte, len(data))
	if decrypt {
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)
		n := int(out[len(out)-1])
		if n < 1 || n > des.BlockSize || n > len(out) {
			return nil, errors.New("3des: bad padding")
		}
		for _, p := range out[len(out)-n:] {
			if int(p) != n {
				return nil, errors.New("3des: bad padding")
			}
		}
		return out[:len(out)-n], nil
	}
	pad := des.BlockSize - len(data)%des.BlockSize
	in := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out = make([]byte, len(in))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, in)
	return out, nil
}

const timestampLayout = "2006-01-02T15:04:05Z"

// login answers 0x608: unwrap the 24-byte 3DES key (RSA-OAEP, SHA-1, empty
// label), decrypt the password blob (20-byte password padded with the fill byte
// 20-len, then the 20-byte UTC timestamp) and the proxy blob, check the skew
// and that we issued the proxy blob, verify the password with the core and
// return a 28-byte token bound to the account.
func (h *Handler) login(ctx context.Context, body []byte) ([]byte, error) {
	r := &reader{b: body}
	email := cstr(r.lv())
	wrapped := r.lv()
	pwBlob := r.lv()
	proxyEnc := r.lv()
	r.u32()
	if r.bad || email == "" || len(wrapped) != 256 || len(pwBlob) != 48 || len(proxyEnc) == 0 || len(proxyEnc) > 2000 {
		return nil, bad("0x608: malformed request (%d bytes)", len(body))
	}
	// The wrapped key is the RSA block as the console holds it: little-endian.
	k, err := rsa.DecryptOAEP(sha1.New(), nil, h.Key, reverseBytes(wrapped), nil)
	if err != nil || len(k) != 24 {
		return nil, bad("0x608: session key does not unwrap")
	}
	pt, err := des3CBC(k, pwBlob, true)
	if err != nil || len(pt) != 40 {
		return nil, bad("0x608: password blob does not decrypt")
	}
	proxy, err := des3CBC(k, proxyEnc, true)
	if err != nil {
		return nil, bad("0x608: proxy blob does not decrypt")
	}
	ts, err := time.Parse(timestampLayout, string(pt[20:]))
	if err != nil {
		return nil, bad("0x608: timestamp %q", pt[20:])
	}
	skew := h.MaxSkew
	if skew == 0 {
		skew = DefaultMaxSkew
	}
	if d := h.now().Sub(ts); d > skew || d < -skew {
		return nil, deny(http.StatusForbidden, fmt.Sprintf("0x608: clock skew %s", d.Round(time.Second)))
	}
	if !h.proxyKnown(proxy) {
		return nil, deny(http.StatusForbidden, "0x608: unknown or expired proxy blob")
	}
	fill := int(pt[19])
	if fill < 4 || fill > 19 { // password 1..16 chars would give 4..19; the applet enforces 6..16
		return nil, bad("0x608: password padding")
	}
	for _, p := range pt[20-fill : 20] {
		if int(p) != fill {
			return nil, bad("0x608: password padding")
		}
	}
	pw := string(pt[:20-fill])

	acct, st, err := h.Core.VerifyPassword(ctx, email, pw)
	var ce *accountcore.Error
	switch {
	case errors.As(err, &ce) && ce.Code == accountcore.CodeUnauthenticated:
		return nil, deny(http.StatusUnauthorized, "0x608: invalid credentials")
	case err != nil:
		h.log().Error("verify password", "err", err)
		return nil, deny(http.StatusServiceUnavailable, "account service unavailable")
	case acct == "" || st != accountcore.StatusActive:
		return nil, deny(http.StatusForbidden, "0x608: account not active")
	}
	tok, err := h.Store.NewToken(acct, email)
	if err != nil {
		return nil, err
	}
	h.log().Info("login", "account", acct)
	return tok, nil
}

// ---- identity of a signed-in session ----

// identity resolves the online XUID and gamertag of a token's account. The XUID
// is the stored one, else the subject of the account's active x360 link, else
// derived (Store.OnlineXUID). The gamertag is the link's public code, else a
// name made from the email's local part [guess: the client offers no display name].
func (h *Handler) identity(ctx context.Context, tok []byte) (acct string, xuid uint64, tag string, err error) {
	acct, email, ok := h.Store.Token(tok)
	if !ok {
		return "", 0, "", deny(http.StatusUnauthorized, "unknown or expired token")
	}
	return h.identityOf(ctx, acct, email)
}

// identityOf is identity for a known account and its sign-in email.
func (h *Handler) identityOf(ctx context.Context, acct, email string) (_ string, xuid uint64, tag string, err error) {
	l, err := h.Core.ActiveXboxLink(ctx, acct)
	if err != nil {
		h.log().Error("active link", "err", err)
		return "", 0, "", deny(http.StatusServiceUnavailable, "account service unavailable")
	}
	var pref uint64
	if l != nil {
		if len(l.SubjectID) == 16 {
			if v, e := strconv.ParseUint(l.SubjectID, 16, 64); e == nil && v>>48 == 0x0009 {
				pref = v
			}
		}
		tag = l.PublicCode
	}
	if xuid, err = h.Store.OnlineXUID(acct, pref); err != nil {
		return "", 0, "", err
	}
	if tag == "" {
		tag = gamertagFrom(email, xuid)
	}
	return acct, xuid, tag, nil
}

// gamertagFrom builds a legal-looking gamertag (letters, digits, spaces, at
// most 15, starting with a letter) from an email's local part.
func gamertagFrom(email string, xuid uint64) string {
	local, _, _ := strings.Cut(email, "@")
	var b []byte
	for i := 0; i < len(local) && len(b) < 15; i++ {
		c := local[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			b = append(b, c)
		case c >= '0' && c <= '9' && len(b) > 0:
			b = append(b, c)
		}
	}
	if len(b) == 0 {
		return fmt.Sprintf("Player%04x", xuid&0xffff)
	}
	return string(b)
}

// ---- 0x60E, 0x624, 0x1707 ----

func (h *Handler) gamertag(ctx context.Context, body []byte) ([]byte, error) {
	if len(body) != 28 {
		return nil, bad("0x60E: body is %d bytes, want 28", len(body))
	}
	_, xuid, tag, err := h.identity(ctx, body)
	if err != nil {
		return nil, err
	}
	out := binary.LittleEndian.AppendUint64(nil, xuid)
	return str(out, tag), nil
}

func (h *Handler) userType(body []byte) ([]byte, error) {
	r := &reader{b: body}
	r.u64()
	r.lv()
	if r.bad {
		return nil, bad("0x624: malformed request (%d bytes)", len(body))
	}
	return []byte{userTypeXenon}, nil
}

func (h *Handler) family(body []byte) ([]byte, error) {
	r := &reader{b: body}
	r.u64()
	n := r.u16()
	r.take(28 * n)
	if r.bad {
		return nil, bad("0x1707: malformed request (%d bytes)", len(body))
	}
	return []byte{0, 0}, nil // no family members
}

// ---- 0x627 ----

// accountInfo answers 0x627 XeGetAccountInfoFromPassport, which the Account
// Recovery applet's time-zone step asks (Lua GetUserLocaleInfoFromPassport ->
// Xbox.Account.GetAccountInfo) before 0x63F. Request: u8[28] token, u64
// machine id, u32 title id. Reply per the XAM 17559 response schema (desc 187):
// first name, last name, u64 date of birth (FILETIME), member name, a 6-string
// address block, a 3-string block, u16 country, 4 u8 flags; strings are
// "u16 len | UTF-8 | NUL". The applet reads FName, DOB and the byte at struct
// offset 0x4a as CountryId (0x53 -> 103/US). In XAM's packed in-memory struct
// (strings 6 bytes {u16 len, ptr}, u64 at 0x0c, blocks at 0x1a and 0x3e, u16
// country at 0x50) 0x4a is the high byte of the third block-2 string's length,
// so any sane reply yields CountryId 0 (confirmed live: CountryInfo id 0). The
// country is still sent where the schema puts it; CountryInfo answers every id.
// We have none of this data beyond the gamertag, so the rest is empty, DOB
// 2000-01-01, country US.
func (h *Handler) accountInfo(ctx context.Context, body []byte) ([]byte, error) {
	r := &reader{b: body}
	tok := r.take(28)
	r.u64()
	r.u32()
	if r.bad || len(r.b) != 0 {
		return nil, bad("0x627: malformed request (%d bytes)", len(body))
	}
	_, _, tag, err := h.identity(ctx, tok)
	if err != nil {
		return nil, err
	}
	const dob2000 = 125911584000000000 // FILETIME of 2000-01-01T00:00Z
	out := str(nil, tag)
	out = str(out, "")
	out = binary.LittleEndian.AppendUint64(out, dob2000)
	out = str(out, "")
	for i := 0; i < 9; i++ {
		out = str(out, "")
	}
	out = binary.LittleEndian.AppendUint16(out, 103) // XC_COUNTRY_US
	return append(out, 0, 0, 0, 0), nil
}

// ---- 0x63F / 0x649 ----

// recover answers 0x63F, the enrol-on-sign-in point: it issues (or looks up) the
// offline XUID and XenonKey for this account on this console and links the
// console (x360-console) and the profile (x360, online XUID, gamertag) to the
// account in the core. A console or profile owned by another account is refused.
// The console is the gateway session's ("<digits>@xbox.com" in AccountHeader);
// [guess] without that header the 12 low decimal digits of the machine id are
// used. 0x649 (TFA receipt / RPS token variant, variable length) is refused.
func (h *Handler) recover(ctx context.Context, body []byte, account string) ([]byte, error) {
	if len(body) != recoverLen {
		return nil, deny(http.StatusNotImplemented, fmt.Sprintf("RecoverAccount: %d-byte body is the 0x649 variant (TFA/RPS), not supported", len(body)))
	}
	r := &reader{b: body}
	machine := r.u64()
	tok := r.take(28)
	want := r.u64()
	dependent := r.take(1)[0]

	acct, xuid, tag, err := h.identity(ctx, tok)
	if err != nil {
		return nil, err
	}
	if xuid != want {
		return nil, deny(http.StatusForbidden, fmt.Sprintf("0x63F: XUID %016x is not the token's account XUID", want))
	}
	if dependent != 0 {
		h.log().Info("dependent account flag set; served as normal", "account", acct)
	}
	digits := consoleDigits(account)
	if digits == "" {
		digits = fmt.Sprintf("%012d", machine%1_000_000_000_000)
		h.log().Warn("no console in the request path, using machine id digits [guess]", "digits", digits)
	}
	err = h.Core.Enrol(ctx, acct, accountcore.SignInRequest{ConsoleDigits: digits, XUID: xuid, Gamertag: tag})
	switch {
	case errors.Is(err, accountcore.ErrConsoleOwned), errors.Is(err, accountcore.ErrUserOwned):
		return nil, deny(http.StatusForbidden, "0x63F: "+err.Error())
	case err != nil:
		h.log().Error("enrol", "err", err)
		return nil, deny(http.StatusServiceUnavailable, "account service unavailable")
	}
	offline, key, err := h.Store.Profile(acct, digits, tag)
	if err != nil {
		return nil, err
	}
	h.log().Info("recover account", "account", acct, "console", digits, "online", fmt.Sprintf("%016x", xuid), "offline", fmt.Sprintf("%016x", offline))
	out := binary.LittleEndian.AppendUint64(nil, xuid)
	out = binary.LittleEndian.AppendUint64(out, offline)
	out = append(out, key...)
	out = str(out, tag)
	out = str(out, Domain)
	return str(out, Realm), nil
}

// consoleDigits extracts the 12 digits from "<digits>@xbox.com".
func consoleDigits(account string) string {
	d, _, _ := strings.Cut(account, "@")
	if len(d) != 12 {
		return ""
	}
	for _, c := range d {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return d
}

// reverseBytes returns a reversed copy (big-endian <-> little-endian integer bytes).
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

package xuacs

// Windows Live ID (Passport) login for the Xbox 360 user logon.
//
// XamUserLogon of a profile with Live credentials asks XAM's WLID engine for a
// ticket for service XUACS.XBOXLIVE.COM, policy MBI, before the user's Kerberos
// AS exchange. The engine (17559 XAM 0x81996000-0x819A4000, state machine
// FUN_8199AA88) talks HTTPS to two Microsoft hosts that DNS sends here:
//
//	GET  nexus.passport.com/federationmetadata/2006-12/FederationMetaData.xml
//	     -> <fed:TargetServiceEndpoint><wsa:Address>  = the RST URL
//	GET  login.live.com/.well-known/openid-configuration -> "token_endpoint"
//	POST <RST host>/ppsecure/deviceaddcredential.srf  (device add, first logon)
//	POST <RST URL>  device RST, AppliesTo http://Passport.NET/tb -> device token
//	POST <token_endpoint>  OAuth password grant (or refresh_token grant):
//	     client_id, grant_type=password, scope=service::XUACS.XBOXLIVE.COM::MBI,
//	     username, password, XboxDeviceID -> {"access_token", "refresh_token", "expires_in"}
//
// The access token becomes the client's "t=<base64>" ticket; XAM base64-decodes
// it (at most 800 bytes) and sends it to XEAS inside padata 0xDA of the user
// AS-REQ, where x360-kdc asks this service (internal API) whether it is ours.
//
// The parsers are strstr-based with exact tags and no entity decoding, so the
// replies below are written as literal strings. Bodies stay under 0x4000 bytes.
// No certificate chain is checked by XAM for these hosts (name and dates only),
// so tlsfront's own CA serves them.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openpak/x360-kdc/internal/accountcore"
)

// WLID host names and paths.
const (
	WLIDNexusHost  = "nexus.passport.com"
	WLIDLoginHost  = "login.live.com"
	wlidFedPath    = "/federationmetadata/2006-12/federationmetadata.xml"
	wlidOIDCPath   = "/.well-known/openid-configuration"
	wlidDevAddPath = "/ppsecure/deviceaddcredential.srf"
	wlidRSTPath    = "/rst2.srf"
	wlidTokenPath  = "/oauth20_token.srf"

	// WLIDTicketTTL is the access token's lifetime; the refresh token's is
	// WLIDRefreshTTL (the client keeps it about 91 days).
	WLIDTicketTTL  = 24 * time.Hour
	WLIDRefreshTTL = 90 * 24 * time.Hour

	wlidScope = "service::XUACS.XBOXLIVE.COM::MBI"

	magicTicket  = "OPW1"
	magicRefresh = "OPR1"
)

// LoadOrCreateWLIDKey reads the 32-byte key that signs the WLID tickets,
// creating it (0600) when missing.
func LoadOrCreateWLIDKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: want 32 bytes, have %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return b, os.WriteFile(path, b, 0o600)
}

// WLIDTicket is what a signed ticket names.
type WLIDTicket struct {
	Account string
	XUID    uint64
	Expires time.Time
}

// sealTicket: magic[4] | u64 BE expiry (unix) | u64 BE online XUID | u8 len | account | HMAC-SHA256[32].
func (h *Handler) sealTicket(magic string, t WLIDTicket) []byte {
	b := []byte(magic)
	b = binary.BigEndian.AppendUint64(b, uint64(t.Expires.Unix()))
	b = binary.BigEndian.AppendUint64(b, t.XUID)
	b = append(b, byte(len(t.Account)))
	b = append(b, t.Account...)
	m := hmac.New(sha256.New, h.WLIDKey)
	m.Write(b)
	return m.Sum(b)
}

func (h *Handler) openTicket(magic string, b []byte) (*WLIDTicket, error) {
	if len(h.WLIDKey) == 0 {
		return nil, errors.New("no WLID key")
	}
	if len(b) < 4+8+8+1+32 || string(b[:4]) != magic {
		return nil, errors.New("not an OpenPak WLID ticket")
	}
	body, mac := b[:len(b)-32], b[len(b)-32:]
	m := hmac.New(sha256.New, h.WLIDKey)
	m.Write(body)
	if !hmac.Equal(m.Sum(nil), mac) {
		return nil, errors.New("ticket signature")
	}
	n := int(body[20])
	if len(body) != 21+n {
		return nil, errors.New("ticket length")
	}
	t := &WLIDTicket{
		Expires: time.Unix(int64(binary.BigEndian.Uint64(body[4:])), 0),
		XUID:    binary.BigEndian.Uint64(body[12:]),
		Account: string(body[21:]),
	}
	if h.now().After(t.Expires) {
		return nil, errors.New("ticket expired")
	}
	return t, nil
}

// VerifyWLIDTicket checks a decoded access token (the bytes the console puts
// in padata 0xDA).
func (h *Handler) VerifyWLIDTicket(b []byte) (*WLIDTicket, error) {
	return h.openTicket(magicTicket, b)
}

// WLID returns the handler for the TLS listener (both host names).
func (h *Handler) WLID() http.Handler {
	return http.HandlerFunc(h.serveWLID)
}

func (h *Handler) serveWLID(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw, status: http.StatusOK}
	log := h.log()
	host := strings.ToLower(r.Host)
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	path := strings.ToLower(r.URL.Path)
	log.Info("wlid request", "method", r.Method, "host", host, "path", r.URL.Path,
		"user_agent", r.Header.Get("User-Agent"), "content_type", r.Header.Get("Content-Type"),
		"content_length", r.ContentLength, "remote", r.RemoteAddr)
	defer func() { log.Info("wlid response", "path", r.URL.Path, "status", w.status) }()

	switch {
	case r.Method == http.MethodGet && path == wlidFedPath:
		reply(w, "text/xml", h.federationMetadata())
	case r.Method == http.MethodGet && path == wlidOIDCPath:
		reply(w, "application/json", `{"issuer":"https://`+WLIDLoginHost+`/","token_endpoint":"https://`+WLIDLoginHost+`/oauth20_token.srf"}`)
	case r.Method == http.MethodPost && path == wlidDevAddPath:
		h.deviceAdd(w, r)
	case r.Method == http.MethodPost && path == wlidRSTPath:
		h.rst(w, r)
	case r.Method == http.MethodPost && path == wlidTokenPath:
		h.oauthToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func reply(w http.ResponseWriter, ctype, body string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
}

// federationMetadata names the RST endpoint (FUN_81998BC0 reads
// <fed:Federation> -> <fed:TargetServiceEndpoint> -> <wsa:Address>).
func (h *Handler) federationMetadata() string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:federation:MicrosoftOnline">` +
		`<RoleDescriptor xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:wsa="http://www.w3.org/2005/08/addressing">` +
		`<fed:Federation>` +
		`<fed:TargetServiceEndpoint><wsa:Address>https://` + WLIDLoginHost + `/RST2.srf</wsa:Address></fed:TargetServiceEndpoint>` +
		`</fed:Federation></RoleDescriptor></EntityDescriptor>`
}

// deviceAdd answers the device credential registration (FUN_81998CC0 wants
// `<DeviceAddResponse Success="true">` and a hex <puid>). The device name and
// password are random per console; nothing about them is trusted later.
func (h *Handler) deviceAdd(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	name := between(body, "<Membername>", "</Membername>")
	var p [8]byte
	rand.Read(p[:])
	p[0] &= 0x0f
	h.log().Info("wlid device add", "membername", name)
	reply(w, "text/xml", `<?xml version="1.0" encoding="utf-8"?><DeviceAddResponse Success="true"><puid>`+
		strings.ToUpper(hex.EncodeToString(p[:]))+`</puid></DeviceAddResponse>`)
}

// rst answers a WS-Trust RST. The device RST (AppliesTo http://Passport.NET/tb)
// gets an opaque device token; the user RST (only when the profile has no
// offline XUID, not the Download Profile path) gets a Compact0 ticket after
// the password check.
func (h *Handler) rst(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	user := between(body, "<wsse:Username>", "</wsse:Username>")
	pass := xmlUnescape(between(body, "<wsse:Password>", "</wsse:Password>"))
	applies := between(body, "<wsa:Address>", "</wsa:Address>")
	now := h.now().UTC()
	exp := now.Add(WLIDTicketTTL)
	lifetime := `<wst:Lifetime><wsu:Created>` + now.Format(timestampLayout) + `</wsu:Created><wsu:Expires>` +
		exp.Format(timestampLayout) + `</wsu:Expires></wst:Lifetime>`
	var tok string
	if strings.Contains(body, `wsu:Id="devicesoftware"`) || strings.EqualFold(applies, "http://Passport.NET/tb") {
		var d [24]byte
		rand.Read(d[:])
		tok = `<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="devicesoftware">` +
			base64.StdEncoding.EncodeToString(d[:]) + `</EncryptedData>`
		h.log().Info("wlid device token", "device", user, "applies_to", applies)
	} else {
		t, err := h.passwordTicket(r, user, pass, "")
		if err != nil {
			h.soapFault(w, err)
			return
		}
		tok = `<wsse:BinarySecurityToken Id="Compact0">t=` + base64.StdEncoding.EncodeToString(t) + `</wsse:BinarySecurityToken>`
	}
	reply(w, "application/soap+xml", `<?xml version="1.0" encoding="utf-8"?>`+
		`<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" `+
		`xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" `+
		`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">`+
		`<S:Body><wst:RequestSecurityTokenResponse>`+
		`<wst:TokenType>urn:passport:compact</wst:TokenType>`+
		`<wst:RequestedSecurityToken>`+tok+`</wst:RequestedSecurityToken>`+
		lifetime+
		`</wst:RequestSecurityTokenResponse></S:Body></S:Envelope>`)
}

// soapFault: psf:value 0x80048821 (bad credentials) maps to logon HR
// 0x80151011 in XAM; anything else to 0x80151103.
func (h *Handler) soapFault(w http.ResponseWriter, err error) {
	code := "0x80048800"
	var re *reqErr
	if errors.As(err, &re) && re.status == http.StatusUnauthorized {
		code = "0x80048821"
	}
	h.log().Info("wlid refused", "reason", err.Error(), "psf", code)
	w.Header().Set("Content-Type", "application/soap+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault"><S:Body><S:Fault>` +
		`<S:Code><S:Value>S:Sender</S:Value></S:Code><S:Reason><S:Text xml:lang="en-US">Authentication Failure</S:Text></S:Reason>` +
		`<S:Detail><psf:error><psf:value>` + code + `</psf:value></psf:error></S:Detail></S:Fault></S:Body></S:Envelope>`))
}

// oauthToken is the token endpoint: password grant (email + password checked
// in the account core) or refresh_token grant (our signed refresh token).
// Replies use no JSON escaping: XAM copies values between quotes verbatim.
func (h *Handler) oauthToken(w http.ResponseWriter, r *http.Request) {
	form, err := url.ParseQuery(readBody(r))
	if err != nil {
		h.oauthError(w, "invalid_request", "form")
		return
	}
	scope := form.Get("scope")
	device := form.Get("XboxDeviceID")
	var t *WLIDTicket
	switch form.Get("grant_type") {
	case "password":
		b, err := h.passwordTicket(r, form.Get("username"), form.Get("password"), device)
		if err != nil {
			var re *reqErr
			if errors.As(err, &re) && re.status == http.StatusUnauthorized {
				h.oauthError(w, "invalid_grant", err.Error())
			} else {
				h.oauthError(w, "temporarily_unavailable", err.Error())
			}
			return
		}
		t, _ = h.VerifyWLIDTicket(b)
	case "refresh_token":
		raw, err := base64.RawURLEncoding.DecodeString(form.Get("refresh_token"))
		if err != nil {
			h.oauthError(w, "invalid_grant", "refresh token encoding")
			return
		}
		rt, err := h.openTicket(magicRefresh, raw)
		if err != nil {
			h.oauthError(w, "invalid_grant", "refresh token: "+err.Error())
			return
		}
		l, err := h.Core.ActiveXboxLink(r.Context(), rt.Account)
		if err != nil {
			h.oauthError(w, "temporarily_unavailable", "account core")
			return
		}
		if l == nil {
			h.oauthError(w, "invalid_grant", "account has no active Xbox 360 profile link")
			return
		}
		t = &WLIDTicket{Account: rt.Account, XUID: rt.XUID, Expires: h.now().Add(WLIDTicketTTL)}
	default:
		h.oauthError(w, "unsupported_grant_type", form.Get("grant_type"))
		return
	}
	if t == nil {
		h.oauthError(w, "server_error", "ticket")
		return
	}
	access := base64.StdEncoding.EncodeToString(h.sealTicket(magicTicket, *t))
	refresh := base64.RawURLEncoding.EncodeToString(h.sealTicket(magicRefresh,
		WLIDTicket{Account: t.Account, XUID: t.XUID, Expires: h.now().Add(WLIDRefreshTTL)}))
	h.log().Info("wlid token issued", "grant", form.Get("grant_type"), "account", t.Account,
		"online", fmt.Sprintf("%016x", t.XUID), "scope", scope, "device", device)
	reply(w, "application/json", `{"token_type":"bearer","expires_in":`+strconv.Itoa(int(WLIDTicketTTL/time.Second))+
		`,"scope":"`+wlidScope+`","access_token":"`+access+`","refresh_token":"`+refresh+`","user_id":"`+
		fmt.Sprintf("%016X", t.XUID)+`"}`)
}

func (h *Handler) oauthError(w http.ResponseWriter, code, why string) {
	h.log().Info("wlid refused", "error", code, "reason", why)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`{"error":"` + code + `","error_description":"OpenPak sign-in refused"}`))
}

// passwordTicket verifies the credentials in the account core and seals an
// access ticket for the account's online XUID.
func (h *Handler) passwordTicket(r *http.Request, email, password, device string) ([]byte, error) {
	if email == "" || password == "" {
		return nil, deny(http.StatusUnauthorized, "missing credentials")
	}
	acct, st, err := h.Core.VerifyPassword(r.Context(), email, password)
	var ce *accountcore.Error
	switch {
	case errors.As(err, &ce) && ce.Code == accountcore.CodeUnauthenticated:
		return nil, deny(http.StatusUnauthorized, "invalid credentials")
	case err != nil:
		h.log().Error("verify password", "err", err)
		return nil, deny(http.StatusServiceUnavailable, "account service unavailable")
	case acct == "" || st != accountcore.StatusActive:
		return nil, deny(http.StatusUnauthorized, "account not active")
	}
	_, xuid, _, err := h.identityOf(r.Context(), acct, email)
	if err != nil {
		return nil, err
	}
	return h.sealTicket(magicTicket, WLIDTicket{Account: acct, XUID: xuid, Expires: h.now().Add(WLIDTicketTTL)}), nil
}

func readBody(r *http.Request) string {
	b := make([]byte, 0, 2048)
	buf := make([]byte, 2048)
	for len(b) < maxBody {
		n, err := r.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return string(b)
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, close)
	if j < 0 {
		return ""
	}
	return s[:j]
}

func xmlUnescape(s string) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(s)
}

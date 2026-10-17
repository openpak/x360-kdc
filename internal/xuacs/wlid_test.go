package xuacs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// strstrPath mimics XAM's parser: each tag must follow the previous one.
func strstrPath(t *testing.T, body string, tags ...string) string {
	t.Helper()
	s := body
	for _, tag := range tags {
		i := strings.Index(s, tag)
		if i < 0 {
			t.Fatalf("tag %q not found in %s", tag, body)
		}
		s = s[i+len(tag):]
	}
	return s
}

func TestWLIDFlow(t *testing.T) {
	r := newRig(t, "")
	r.h.WLIDKey = bytes.Repeat([]byte{7}, 32)
	srv := httptest.NewServer(r.h.WLID())
	defer srv.Close()
	do := func(method, path, ctype, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Host = WLIDLoginHost
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	st, fed := do("GET", "/federationmetadata/2006-12/FederationMetaData.xml", "", "")
	rest := strstrPath(t, fed, "<fed:Federation>", "<fed:TargetServiceEndpoint>", "<wsa:Address>")
	if st != 200 || !strings.HasPrefix(rest, "https://login.live.com/RST2.srf</wsa:Address>") {
		t.Fatalf("federation: %d %s", st, fed)
	}
	st, oidc := do("GET", "/.well-known/openid-configuration", "", "")
	if st != 200 || !strings.Contains(oidc, `"token_endpoint":"https://login.live.com/oauth20_token.srf"`) {
		t.Fatalf("openid: %d %s", st, oidc)
	}
	st, dev := do("POST", "/ppsecure/deviceaddcredential.srf", "application/soap+xml",
		`<DeviceAddRequest><ClientInfo name="FE5B80E5-82FB-4060-AAFE-AC5C4605EA76" version="1.0"/><Authentication><Membername>11Xe0123456789</Membername><Password>0123456789abcdef</Password></Authentication></DeviceAddRequest>`)
	if st != 200 || !strings.HasPrefix(strstrPath(t, dev, `<DeviceAddResponse Success="`), `true">`) || !strings.Contains(dev, "<puid>") {
		t.Fatalf("device add: %d %s", st, dev)
	}
	st, rstr := do("POST", "/RST2.srf", "application/soap+xml",
		`<s:Envelope><s:Header><wsse:Security><wsse:UsernameToken wsu:Id="devicesoftware"><wsse:Username>11Xe0123456789</wsse:Username><wsse:Password>0123456789abcdef</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>http://Passport.NET/tb</wsa:Address></wsa:EndpointReference></wsp:AppliesTo></wst:RequestSecurityToken></s:Body></s:Envelope>`)
	rest = strstrPath(t, rstr, "<S:Body>", "<wst:RequestSecurityTokenResponse", "<wst:RequestedSecurityToken>")
	if st != 200 || !strings.Contains(rest, "</wst:RequestedSecurityToken>") {
		t.Fatalf("device RST: %d %s", st, rstr)
	}
	created := strstrPath(t, rstr, "<wst:Lifetime>", "<wsu:Created>")
	if i := strings.Index(created, "</wsu:Created>"); i != 20 {
		t.Fatalf("Created is %d chars", i)
	}

	form := url.Values{"client_id": {"bba26dcd-9b84-4bdf-885f-8e83bf118bab"}, "grant_type": {"password"},
		"scope": {wlidScope}, "username": {"ann@example.org"}, "password": {"wrongpw12"}, "XboxDeviceID": {"FA00000012345678"}}
	if st, b := do("POST", "/oauth20_token.srf", "application/x-www-form-urlencoded", form.Encode()); st != 400 || !strings.Contains(b, "invalid_grant") {
		t.Fatalf("wrong password: %d %s", st, b)
	}
	form.Set("password", "secret12")
	st, tokb := do("POST", "/oauth20_token.srf", "application/x-www-form-urlencoded", form.Encode())
	var tr struct {
		Access    string `json:"access_token"`
		Refresh   string `json:"refresh_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if st != 200 || json.Unmarshal([]byte(tokb), &tr) != nil || tr.ExpiresIn <= 0 {
		t.Fatalf("token: %d %s", st, tokb)
	}
	raw, err := base64.StdEncoding.DecodeString(tr.Access)
	if err != nil || len(raw) > 800 {
		t.Fatalf("access token: %v len %d", err, len(raw))
	}
	tk, err := r.h.VerifyWLIDTicket(raw)
	if err != nil || tk.Account != "A-ann" || tk.XUID>>48 != 9 {
		t.Fatalf("ticket: %+v %v", tk, err)
	}
	if strings.ContainsAny(tr.Refresh, `"+/=`) {
		t.Fatalf("refresh token not url-safe: %s", tr.Refresh)
	}

	// internal API: ticket check and user key after a profile exists.
	isrv := httptest.NewServer(r.h.Internal("0123456789abcdef"))
	defer isrv.Close()
	ipost := func(key, path, body string) (int, map[string]string) {
		req, _ := http.NewRequest("POST", isrv.URL+path, strings.NewReader(body))
		req.Header.Set(InternalKeyHeader, key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]string
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	if st, _ := ipost("wrong", "/internal/v1/wlid-ticket", `{}`); st != 403 {
		t.Fatalf("internal key not enforced: %d", st)
	}
	st, m := ipost("0123456789abcdef", "/internal/v1/wlid-ticket", `{"ticket":"`+tr.Access+`"}`)
	if st != 200 || m["account"] != "A-ann" {
		t.Fatalf("wlid-ticket: %d %v", st, m)
	}
	bad := append([]byte{}, raw...)
	bad[10] ^= 1
	if st, _ := ipost("0123456789abcdef", "/internal/v1/wlid-ticket", `{"ticket":"`+base64.StdEncoding.EncodeToString(bad)+`"}`); st != 403 {
		t.Fatalf("tampered ticket accepted: %d", st)
	}
	off, key, err := r.h.Store.Profile("A-ann", "478700668470", "Ann Smith")
	if err != nil || off == 0 {
		t.Fatal(err)
	}
	st, m = ipost("0123456789abcdef", "/internal/v1/user-key", `{"console":"478700668470","gamertag":"ann_smith"}`)
	if st != 200 || m["xenon_key"] != hexStr(key) || m["account"] != "A-ann" {
		t.Fatalf("user-key: %d %v", st, m)
	}
	if st, _ := ipost("0123456789abcdef", "/internal/v1/user-key", `{"console":"478700668470","gamertag":"bob"}`); st != 404 {
		t.Fatalf("unknown gamertag: %d", st)
	}

	// refresh grant
	rf := url.Values{"client_id": {"x"}, "grant_type": {"refresh_token"}, "refresh_token": {tr.Refresh}, "scope": {wlidScope}}
	if st, b := do("POST", "/oauth20_token.srf", "application/x-www-form-urlencoded", rf.Encode()); st != 400 {
		// no active profile link in the fake core yet: refused
		t.Fatalf("refresh without link: %d %s", st, b)
	}
}

func hexStr(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

package config

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var required = map[string]string{"X360_KDC_XMACS_KEY": "k.pem", "X360_KDC_CONSOLE_CA": "ca.pem"}

func with(extra map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range required {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(with(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":88" || c.Accounts != "x360-accounts.json" || c.TicketKey != "x360-ticket-key.bin" || c.SGAddress.String() != "10.0.2.2" || c.Debug {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(with(map[string]string{"X360_KDC_ADDR": "127.0.0.1:18088", "X360_KDC_ACCOUNTS": "/a.json",
		"X360_KDC_TICKET_KEY": "/t.bin", "X360_KDC_SG_ADDRESS": "203.0.113.9", "X360_KDC_DEBUG": "yes"})))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:18088" || c.Accounts != "/a.json" || c.TicketKey != "/t.bin" || c.SGAddress.String() != "203.0.113.9" || !c.Debug {
		t.Fatalf("overrides: %+v", c)
	}
}

func TestRequiredAndInvalid(t *testing.T) {
	if _, err := Load(env(map[string]string{"X360_KDC_CONSOLE_CA": "ca.pem"})); err == nil {
		t.Fatal("missing XMACS key accepted")
	}
	if _, err := Load(env(map[string]string{"X360_KDC_XMACS_KEY": "k.pem"})); err == nil {
		t.Fatal("missing CA accepted")
	}
	for _, bad := range []string{"not-an-ip", "::1", "10.0.2.2/24"} {
		if _, err := Load(env(with(map[string]string{"X360_KDC_SG_ADDRESS": bad}))); err == nil {
			t.Fatalf("SG address %q accepted", bad)
		}
	}
}

func TestGatewayConfig(t *testing.T) {
	if _, err := LoadGateway(env(nil)); err == nil {
		t.Fatal("missing required keys accepted")
	}
	c, err := LoadGateway(env(map[string]string{
		"X360_GATEWAY_TICKET_KEY": "t.bin", "X360_GATEWAY_ACCOUNTS": "a.json", "X360_GATEWAY_CONSOLE_CA": "ca.pem",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":3074" || c.TicketKey != "t.bin" || c.Accounts != "a.json" || c.ConsoleCA != "ca.pem" || c.Debug || c.ServiceURL != DefaultServiceURL {
		t.Fatalf("gateway config: %+v", c)
	}
}

func TestGatewayServiceURL(t *testing.T) {
	base := map[string]string{"X360_GATEWAY_TICKET_KEY": "t", "X360_GATEWAY_ACCOUNTS": "a", "X360_GATEWAY_CONSOLE_CA": "c"}
	base["X360_GATEWAY_SERVICE_URL"] = "http://145.241.199.19"
	c, err := LoadGateway(env(base))
	if err != nil || c.ServiceURL != "http://145.241.199.19" {
		t.Fatalf("%+v %v", c, err)
	}
	base["X360_GATEWAY_SERVICE_URL"] = "145.241.199.19"
	if _, err := LoadGateway(env(base)); err == nil {
		t.Fatal("scheme-less URL accepted")
	}
}

func TestLiveInfoConfig(t *testing.T) {
	c, err := LoadLiveInfo(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":25" || c.SMRevision != "" || c.PollMinutes != 120 || c.Debug {
		t.Fatalf("defaults: %+v", c)
	}
	c, err = LoadLiveInfo(env(map[string]string{"X360_LIVEINFO_ADDR": "127.0.0.1:18025",
		"X360_LIVEINFO_SMREVISION": "126d69eb6cf3737c", "X360_LIVEINFO_POLL_MINUTES": "60", "X360_LIVEINFO_DEBUG": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:18025" || c.SMRevision != "126d69eb6cf3737c" || c.PollMinutes != 60 || !c.Debug {
		t.Fatalf("overrides: %+v", c)
	}
	for _, m := range []map[string]string{
		{"X360_LIVEINFO_SMREVISION": "xyz"}, {"X360_LIVEINFO_POLL_MINUTES": "10"},
		{"X360_LIVEINFO_POLL_MINUTES": "300"}, {"X360_LIVEINFO_POLL_MINUTES": "abc"},
	} {
		if _, err := LoadLiveInfo(env(m)); err == nil {
			t.Fatalf("accepted %v", m)
		}
	}
}

func TestLiveInfoHiveExtra(t *testing.T) {
	c, err := LoadLiveInfo(env(nil))
	if err != nil || c.Extra != nil {
		t.Fatalf("unset extra: %+v %v", c, err)
	}
	c, err = LoadLiveInfo(env(map[string]string{"X360_LIVEINFO_HIVE_EXTRA": " XboxXPassportUriRoot=http://145.241.199.19/passport;" +
		"LiveServiceUrl.presence=http://145.241.199.19/presence;Eq=a=b "}))
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{
		{"Eq", "a=b"},
		{"LiveServiceUrl.presence", "http://145.241.199.19/presence"},
		{"XboxXPassportUriRoot", "http://145.241.199.19/passport"},
	}
	if len(c.Extra) != len(want) {
		t.Fatalf("extra %v", c.Extra)
	}
	for i := range want {
		if c.Extra[i] != want[i] {
			t.Fatalf("extra[%d] %v, want %v", i, c.Extra[i], want[i])
		}
	}
	for _, v := range []string{"novalue", "a=1;;b=2", "=x", "  =x", "a=1;b", "a=1;a=2"} {
		if _, err := LoadLiveInfo(env(map[string]string{"X360_LIVEINFO_HIVE_EXTRA": v})); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
}

func TestAccountCoreConfig(t *testing.T) {
	c, err := Load(env(with(map[string]string{"X360_KDC_ACCOUNT_CORE_URL": "http://core:7000", "X360_KDC_ACCOUNT_CORE_TOKEN": "k"})))
	if err != nil || c.CoreURL != "http://core:7000" || c.CoreToken != "k" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, m := range []map[string]string{
		{"X360_KDC_ACCOUNT_CORE_URL": "http://core:7000"},
		{"X360_KDC_ACCOUNT_CORE_TOKEN": "k"},
	} {
		if _, err := Load(env(with(m))); err == nil {
			t.Fatalf("accepted %v", m)
		}
	}
}

func TestParseServiceURLs(t *testing.T) {
	m, err := ParseServiceURLs("80=http://145.241.199.19; 5=http://145.241.199.19:10005")
	if err != nil || len(m) != 2 || m[5] != "http://145.241.199.19:10005" || m[80] != "http://145.241.199.19" {
		t.Fatalf("%v %v", m, err)
	}
	if m, err := ParseServiceURLs(""); m != nil || err != nil {
		t.Fatal("empty")
	}
	for _, bad := range []string{"80", "x=http://a", "0=http://a", "5=ftp://a", "5=http://a;5=http://b", "70000=http://a"} {
		if _, err := ParseServiceURLs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

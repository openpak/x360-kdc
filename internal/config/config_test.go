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
	if c.Addr != ":3074" || c.TicketKey != "t.bin" || c.Accounts != "a.json" || c.ConsoleCA != "ca.pem" || c.Debug {
		t.Fatalf("gateway config: %+v", c)
	}
}

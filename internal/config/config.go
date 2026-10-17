// Package config loads x360-kdc configuration from the environment.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// DefaultSGAddress is the security-gateway IPv4 advertised in the TGS reply's
// D7 record. 10.0.2.2 is the emulator's view of its host and is right only
// for a local Wharf test; a deployment must set the public SG address.
const DefaultSGAddress = "10.0.2.2"

type Config struct {
	Addr      string     // X360_KDC_ADDR, default :88 (UDP; the firmware dials 88)
	XMACSKey  string     // X360_KDC_XMACS_KEY: RSA-2048 private key PEM for the MACS OAEP block
	ConsoleCA string     // X360_KDC_CONSOLE_CA: RSA-2048 public key PEM, the console certificate trust anchor
	Accounts  string     // X360_KDC_ACCOUNTS: JSON account store, created 0600 on first provisioning
	TicketKey string     // X360_KDC_TICKET_KEY: 16-byte ticket key file, created 0600 when missing
	SGAddress netip.Addr // X360_KDC_SG_ADDRESS: IPv4 in the D7 record
	Debug     bool       // X360_KDC_DEBUG
	// OpenPak account core (gRPC). Both empty: local store only (dev). Both set:
	// MACS requires an active console pairing in the core.
	CoreURL   string // X360_KDC_ACCOUNT_CORE_URL, e.g. http://127.0.0.1:7000
	CoreToken string // X360_KDC_ACCOUNT_CORE_TOKEN, the core's internal key
}

// Load reads the environment through getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		Addr:      getenv("X360_KDC_ADDR"),
		XMACSKey:  getenv("X360_KDC_XMACS_KEY"),
		ConsoleCA: getenv("X360_KDC_CONSOLE_CA"),
		Accounts:  getenv("X360_KDC_ACCOUNTS"),
		TicketKey: getenv("X360_KDC_TICKET_KEY"),
		Debug:     isTrue(getenv("X360_KDC_DEBUG")),

		CoreURL:   getenv("X360_KDC_ACCOUNT_CORE_URL"),
		CoreToken: getenv("X360_KDC_ACCOUNT_CORE_TOKEN"),
	}
	if (c.CoreURL == "") != (c.CoreToken == "") {
		return nil, fmt.Errorf("X360_KDC_ACCOUNT_CORE_URL and X360_KDC_ACCOUNT_CORE_TOKEN must be set together")
	}
	if c.Addr == "" {
		c.Addr = ":88"
	}
	if c.XMACSKey == "" {
		return nil, fmt.Errorf("X360_KDC_XMACS_KEY is required")
	}
	if c.ConsoleCA == "" {
		return nil, fmt.Errorf("X360_KDC_CONSOLE_CA is required")
	}
	if c.Accounts == "" {
		c.Accounts = "x360-accounts.json"
	}
	if c.TicketKey == "" {
		c.TicketKey = "x360-ticket-key.bin"
	}
	sg := getenv("X360_KDC_SG_ADDRESS")
	if sg == "" {
		sg = DefaultSGAddress
	}
	addr, err := netip.ParseAddr(sg)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("X360_KDC_SG_ADDRESS must be an IPv4 address")
	}
	c.SGAddress = addr
	return c, nil
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// DefaultGatewayAddr is the security gateway's UDP port, which the firmware
// dials on the address the D7 record carries.
const DefaultGatewayAddr = ":3074"

// DefaultServiceURL is the LiveHive backend the service transport proxies to.
const DefaultServiceURL = "http://openpak-x360-liveinfo:10025"

// GatewayConfig is the x360-gateway configuration. It shares the KDC's ticket
// key file, account store and console CA trust anchor, read-only.
type GatewayConfig struct {
	Addr      string // X360_GATEWAY_ADDR, default :3074
	TicketKey string // X360_GATEWAY_TICKET_KEY: the KDC's 16-byte ticket key file (never created here)
	Accounts  string // X360_GATEWAY_ACCOUNTS: the KDC's account store, re-read on each initiation
	ConsoleCA string // X360_GATEWAY_CONSOLE_CA: console CA public key PEM, to re-verify stored certificates
	// ServiceURL is the HTTP backend of the service transport (X360_GATEWAY_SERVICE_URL).
	ServiceURL string
	// ServiceURLs is X360_GATEWAY_SERVICE_URLS ("port=url;port=url"): per destination port
	// overrides of ServiceURL, which stays the default for every other port.
	ServiceURLs map[uint16]string
	Debug       bool // X360_GATEWAY_DEBUG
}

// LoadGateway reads the gateway environment through getenv.
func LoadGateway(getenv func(string) string) (*GatewayConfig, error) {
	c := &GatewayConfig{
		Addr:       getenv("X360_GATEWAY_ADDR"),
		TicketKey:  getenv("X360_GATEWAY_TICKET_KEY"),
		Accounts:   getenv("X360_GATEWAY_ACCOUNTS"),
		ConsoleCA:  getenv("X360_GATEWAY_CONSOLE_CA"),
		Debug:      isTrue(getenv("X360_GATEWAY_DEBUG")),
		ServiceURL: strings.TrimSpace(getenv("X360_GATEWAY_SERVICE_URL")),
	}
	if c.Addr == "" {
		c.Addr = DefaultGatewayAddr
	}
	if c.ServiceURL == "" {
		c.ServiceURL = DefaultServiceURL
	}
	if u, err := url.Parse(c.ServiceURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("X360_GATEWAY_SERVICE_URL %q is not an http(s) URL", c.ServiceURL)
	}
	urls, err := ParseServiceURLs(getenv("X360_GATEWAY_SERVICE_URLS"))
	if err != nil {
		return nil, err
	}
	c.ServiceURLs = urls
	for _, r := range []struct{ v, name string }{
		{c.TicketKey, "X360_GATEWAY_TICKET_KEY"},
		{c.Accounts, "X360_GATEWAY_ACCOUNTS"},
		{c.ConsoleCA, "X360_GATEWAY_CONSOLE_CA"},
	} {
		if r.v == "" {
			return nil, fmt.Errorf("%s is required", r.name)
		}
	}
	return c, nil
}

// ParseServiceURLs parses "80=http://host;5=http://host:10005" into a port map.
// Empty input means no overrides.
func ParseServiceURLs(v string) (map[uint16]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	out := map[uint16]string{}
	for _, pair := range strings.Split(v, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		ps, raw, ok := strings.Cut(pair, "=")
		port, err := strconv.ParseUint(strings.TrimSpace(ps), 10, 16)
		raw = strings.TrimSpace(raw)
		if !ok || err != nil || port == 0 {
			return nil, fmt.Errorf("X360_GATEWAY_SERVICE_URLS: %q is not port=url", pair)
		}
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("X360_GATEWAY_SERVICE_URLS: %q is not an http(s) URL", raw)
		}
		if _, dup := out[uint16(port)]; dup {
			return nil, fmt.Errorf("X360_GATEWAY_SERVICE_URLS: port %d given twice", port)
		}
		out[uint16(port)] = raw
	}
	return out, nil
}

// DefaultLiveInfoAddr is the LiveHive HTTP port (Live service 25).
const DefaultLiveInfoAddr = ":25"

// LiveInfoConfig is the x360-liveinfo configuration.
type LiveInfoConfig struct {
	Addr        string // X360_LIVEINFO_ADDR, default :25 (TCP)
	SMRevision  string // X360_LIVEINFO_SMREVISION: optional hex; empty omits the key
	PollMinutes int    // X360_LIVEINFO_POLL_MINUTES, 30..240, default 120
	// Extra are X360_LIVEINFO_HIVE_EXTRA pairs ("key=value;key=value"), sorted by key.
	Extra [][2]string
	Debug bool // X360_LIVEINFO_DEBUG
}

// parseHiveExtra parses "key=value;key=value" into pairs sorted by key. Empty
// input means no extra keys. Keys must be non-empty and unique; the value may
// contain '=' (the hive builder escapes it).
func parseHiveExtra(v string) ([][2]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	var out [][2]string
	seen := map[string]bool{}
	for _, pair := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("X360_LIVEINFO_HIVE_EXTRA: %q is not key=value", pair)
		}
		if seen[k] {
			return nil, fmt.Errorf("X360_LIVEINFO_HIVE_EXTRA: key %q given twice", k)
		}
		seen[k] = true
		out = append(out, [2]string{k, strings.TrimSpace(val)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out, nil
}

// LoadLiveInfo reads the LiveHive environment through getenv.
func LoadLiveInfo(getenv func(string) string) (*LiveInfoConfig, error) {
	c := &LiveInfoConfig{
		Addr:        getenv("X360_LIVEINFO_ADDR"),
		SMRevision:  strings.TrimSpace(getenv("X360_LIVEINFO_SMREVISION")),
		PollMinutes: 120,
		Debug:       isTrue(getenv("X360_LIVEINFO_DEBUG")),
	}
	if c.Addr == "" {
		c.Addr = DefaultLiveInfoAddr
	}
	for _, r := range c.SMRevision {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return nil, fmt.Errorf("X360_LIVEINFO_SMREVISION must be a hex string")
		}
	}
	if v := strings.TrimSpace(getenv("X360_LIVEINFO_POLL_MINUTES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 || n > 240 {
			return nil, fmt.Errorf("X360_LIVEINFO_POLL_MINUTES must be 30..240")
		}
		c.PollMinutes = n
	}
	extra, err := parseHiveExtra(getenv("X360_LIVEINFO_HIVE_EXTRA"))
	if err != nil {
		return nil, err
	}
	c.Extra = extra
	return c, nil
}

// DefaultXUACSAddr is the xuacs HTTP port (Live service 5; the port is the service id).
const DefaultXUACSAddr = ":5"

// XUACSConfig is the x360-xuacs configuration.
type XUACSConfig struct {
	Addr      string // X360_XUACS_ADDR, default :5 (TCP)
	RSAKey    string // X360_XUACS_RSA_KEY: RSA-2048 private key PEM, generated 0600 when missing; default <state>/rsa-key.pem
	State     string // X360_XUACS_STATE: directory for the token store and issued profiles
	CoreURL   string // X360_XUACS_ACCOUNT_CORE_URL (required: passwords are verified there)
	CoreToken string // X360_XUACS_ACCOUNT_CORE_TOKEN
	MaxSkew   string // X360_XUACS_MAX_SKEW: optional Go duration, default 5m
	Debug     bool   // X360_XUACS_DEBUG
	// TLSAddr serves the Windows Live ID hosts (nexus.passport.com,
	// login.live.com) with leaves from a CA kept in <state>/wlid-ca; empty: off.
	TLSAddr string // X360_XUACS_TLS_ADDR, e.g. :10443
	// InternalAddr serves the internal API x360-kdc uses for the user AS
	// exchange; it needs InternalKey. Empty: off.
	InternalAddr string // X360_XUACS_INTERNAL_ADDR, e.g. :10006
	InternalKey  string // X360_XUACS_INTERNAL_KEY
}

// LoadXUACS reads the xuacs environment through getenv.
func LoadXUACS(getenv func(string) string) (*XUACSConfig, error) {
	c := &XUACSConfig{
		Addr:      getenv("X360_XUACS_ADDR"),
		RSAKey:    getenv("X360_XUACS_RSA_KEY"),
		State:     getenv("X360_XUACS_STATE"),
		CoreURL:   getenv("X360_XUACS_ACCOUNT_CORE_URL"),
		CoreToken: getenv("X360_XUACS_ACCOUNT_CORE_TOKEN"),
		MaxSkew:   strings.TrimSpace(getenv("X360_XUACS_MAX_SKEW")),
		Debug:     isTrue(getenv("X360_XUACS_DEBUG")),

		TLSAddr:      strings.TrimSpace(getenv("X360_XUACS_TLS_ADDR")),
		InternalAddr: strings.TrimSpace(getenv("X360_XUACS_INTERNAL_ADDR")),
		InternalKey:  strings.TrimSpace(getenv("X360_XUACS_INTERNAL_KEY")),
	}
	if c.InternalAddr != "" && len(c.InternalKey) < 16 {
		return nil, fmt.Errorf("X360_XUACS_INTERNAL_ADDR needs X360_XUACS_INTERNAL_KEY (at least 16 characters)")
	}
	if c.Addr == "" {
		c.Addr = DefaultXUACSAddr
	}
	if c.State == "" {
		c.State = "x360-xuacs-state"
	}
	if c.RSAKey == "" {
		c.RSAKey = strings.TrimRight(c.State, "/") + "/rsa-key.pem"
	}
	if c.CoreURL == "" || c.CoreToken == "" {
		return nil, fmt.Errorf("X360_XUACS_ACCOUNT_CORE_URL and X360_XUACS_ACCOUNT_CORE_TOKEN are required")
	}
	return c, nil
}

// Package config loads x360-kdc configuration from the environment.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
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
	Debug      bool // X360_GATEWAY_DEBUG
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

// DefaultLiveInfoAddr is the LiveHive HTTP port (Live service 25).
const DefaultLiveInfoAddr = ":25"

// LiveInfoConfig is the x360-liveinfo configuration.
type LiveInfoConfig struct {
	Addr        string // X360_LIVEINFO_ADDR, default :25 (TCP)
	SMRevision  string // X360_LIVEINFO_SMREVISION: optional hex; empty omits the key
	PollMinutes int    // X360_LIVEINFO_POLL_MINUTES, 30..240, default 120
	Debug       bool   // X360_LIVEINFO_DEBUG
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
	return c, nil
}

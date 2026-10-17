// Command x360-gateway is OpenPak's Xbox 360 security gateway: the SG
// handshake and secure-channel data packets on UDP 3074. It shares the KDC's
// ticket key, account store and console CA, read-only.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openpak/x360-kdc/internal/accountcore"
	"openpak/x360-kdc/internal/config"
	"openpak/x360-kdc/internal/gateway"
	"openpak/x360-kdc/internal/kdc"
	"openpak/x360-kdc/internal/rc4hmac"
)

func main() {
	cfg, err := config.LoadGateway(os.Getenv)
	level := slog.LevelInfo
	if err == nil && cfg.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	ca, err := kdc.LoadPublicKey(cfg.ConsoleCA)
	if err != nil {
		log.Error("console CA", "err", err)
		os.Exit(2)
	}
	// The ticket key belongs to the KDC: a missing file is an error, never created here.
	ticketKey, err := os.ReadFile(cfg.TicketKey)
	if err != nil || len(ticketKey) != rc4hmac.KeyLen {
		log.Error("ticket key", "path", cfg.TicketKey, "err", err, "len", len(ticketKey))
		os.Exit(2)
	}
	store, err := kdc.OpenStore(cfg.Accounts)
	if err != nil {
		log.Error("accounts", "err", err)
		os.Exit(2)
	}
	addr, err := net.ResolveUDPAddr("udp4", cfg.Addr)
	if err != nil {
		log.Error("address", "err", err)
		os.Exit(2)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("x360-gateway listening", "addr", conn.LocalAddr(), "accounts", store.Len(), "service_url", cfg.ServiceURL, "service_urls", cfg.ServiceURLs, "debug", cfg.Debug)
	g := &gateway.Gateway{TicketKey: ticketKey, AccountsPath: cfg.Accounts, CA: ca, Now: time.Now, Log: log, ServiceURL: cfg.ServiceURL, ServiceURLs: cfg.ServiceURLs}
	// Presence: users signed in on a live session are online in the account
	// core (namespace xbox360). The core URL/token are the KDC's (same env file).
	if u, tok := os.Getenv("X360_KDC_ACCOUNT_CORE_URL"), os.Getenv("X360_KDC_ACCOUNT_CORE_TOKEN"); u != "" && tok != "" {
		core, err := accountcore.New(u, tok, nil)
		if err != nil {
			log.Error("account core", "err", err)
			os.Exit(2)
		}
		p := &gateway.Presence{Gateway: g, Core: core, Log: log, Client: os.Getenv("X360_GATEWAY_PRESENCE_CLIENT")}
		go p.Run(ctx)
		log.Info("presence publishing enabled", "namespace", gateway.PresenceNamespace, "core", u)
	} else {
		log.Warn("presence publishing off: X360_KDC_ACCOUNT_CORE_URL/_TOKEN not set")
	}
	srv := &gateway.Server{Gateway: g, Log: log}
	if err := srv.Serve(ctx, conn); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

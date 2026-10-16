// Command x360-kdc is OpenPak's Xbox 360 Kerberos endpoint: MACS, XEAS and
// XETGS on one UDP socket (port 88).
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
	"openpak/x360-kdc/internal/kdc"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	level := slog.LevelInfo
	if err == nil && cfg.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	priv, err := kdc.LoadPrivateKey(cfg.XMACSKey)
	if err != nil {
		log.Error("XMACS key", "err", err)
		os.Exit(2)
	}
	ca, err := kdc.LoadPublicKey(cfg.ConsoleCA)
	if err != nil {
		log.Error("console CA", "err", err)
		os.Exit(2)
	}
	store, err := kdc.OpenStore(cfg.Accounts)
	if err != nil {
		log.Error("accounts", "err", err)
		os.Exit(2)
	}
	ticketKey, err := kdc.LoadTicketKey(cfg.TicketKey)
	if err != nil {
		log.Error("ticket key", "err", err)
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
	if v := os.Getenv("X360_KDC_D7_SERVICES"); v != "" {
		ids, err := kdc.ParseD7Services(v)
		if err != nil {
			log.Error("X360_KDC_D7_SERVICES", "err", err)
			os.Exit(2)
		}
		kdc.D7Services = ids
	}
	if v := os.Getenv("X360_KDC_D7_EXTENDED"); v != "" {
		ext, err := kdc.ParseD7Extended(v)
		if err != nil {
			log.Error("X360_KDC_D7_EXTENDED", "err", err)
			os.Exit(2)
		}
		kdc.D7Extended = ext
	}
	log.Info("x360-kdc listening", "addr", conn.LocalAddr(), "sg", cfg.SGAddress, "d7_services", kdc.D7Services, "d7_extended", kdc.D7Extended, "accounts", store.Len(), "debug", cfg.Debug)
	h := &kdc.Handler{XMACS: priv, CA: ca, Accounts: store, TicketKey: ticketKey, SGAddress: cfg.SGAddress, Now: time.Now, Log: log}
	if cfg.CoreURL != "" {
		core, err := accountcore.New(cfg.CoreURL, cfg.CoreToken, nil)
		if err != nil {
			log.Error("account core", "err", err)
			os.Exit(2)
		}
		h.Core = &accountcore.Enroller{Core: core, EnrolAccount: cfg.CoreEnrolAccount}
		log.Info("account core enabled: MACS requires an active console pairing", "url", cfg.CoreURL, "enrol_account_set", cfg.CoreEnrolAccount != "")
	} else {
		log.Warn("account core NOT configured: identities come from the local store only (development; production must set X360_KDC_ACCOUNT_CORE_URL and _TOKEN)")
	}
	srv := &kdc.Server{Handler: h, Log: log}
	if err := srv.Serve(ctx, conn); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

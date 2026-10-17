// Command x360-xuacs is OpenPak's Xbox 360 account service (Live service 5): the
// HTTP /xuacs/*.ashx endpoints behind the Download Profile sign-in.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"openpak/x360-kdc/internal/accountcore"
	"openpak/x360-kdc/internal/config"
	"openpak/x360-kdc/internal/tlsfront"
	"openpak/x360-kdc/internal/xuacs"
)

func main() {
	cfg, err := config.LoadXUACS(os.Getenv)
	level := slog.LevelInfo
	if err == nil && cfg.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	core, err := accountcore.New(cfg.CoreURL, cfg.CoreToken, nil)
	if err != nil {
		log.Error("account core", "err", err)
		os.Exit(2)
	}
	key, err := xuacs.LoadOrCreateKey(cfg.RSAKey)
	if err != nil {
		log.Error("rsa key", "err", err)
		os.Exit(2)
	}
	store, err := xuacs.OpenStore(cfg.State, time.Now)
	if err != nil {
		log.Error("state", "err", err)
		os.Exit(2)
	}
	wlidKey, err := xuacs.LoadOrCreateWLIDKey(filepath.Join(cfg.State, "wlid-key.bin"))
	if err != nil {
		log.Error("wlid key", "err", err)
		os.Exit(2)
	}
	h := &xuacs.Handler{Core: xuacs.CoreClient{Client: core}, Key: key, Store: store, Log: log, WLIDKey: wlidKey}
	if cfg.MaxSkew != "" {
		if h.MaxSkew, err = time.ParseDuration(cfg.MaxSkew); err != nil || h.MaxSkew <= 0 {
			log.Error("X360_XUACS_MAX_SKEW", "value", cfg.MaxSkew)
			os.Exit(2)
		}
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("x360-xuacs listening", "addr", ln.Addr(), "state", cfg.State, "rsa_key", cfg.RSAKey, "debug", cfg.Debug)
	go h.RunReconcile(ctx, time.Minute)
	if cfg.TLSAddr != "" {
		front, err := tlsfront.LoadOrCreate(filepath.Join(cfg.State, "wlid-ca"))
		if err != nil {
			log.Error("wlid tls", "err", err)
			os.Exit(2)
		}
		front.Fallback = xuacs.WLIDLoginHost
		tsrv := front.Serve(&http.Server{Addr: cfg.TLSAddr, Handler: h.WLID(), ReadHeaderTimeout: 10 * time.Second,
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelInfo)})
		go func() {
			log.Info("x360-xuacs WLID TLS listening", "addr", cfg.TLSAddr)
			if err := tsrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("wlid serve", "err", err)
				os.Exit(1)
			}
		}()
		go func() { <-ctx.Done(); tsrv.Close() }()
	}
	if cfg.InternalAddr != "" {
		isrv := &http.Server{Addr: cfg.InternalAddr, Handler: h.Internal(cfg.InternalKey), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("x360-xuacs internal API listening", "addr", cfg.InternalAddr)
			if err := isrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("internal serve", "err", err)
				os.Exit(1)
			}
		}()
		go func() { <-ctx.Done(); isrv.Close() }()
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

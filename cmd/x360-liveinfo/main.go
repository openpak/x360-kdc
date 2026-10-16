// Command x360-liveinfo is OpenPak's Xbox 360 LiveHive endpoint: the HTTP
// /liveinfo/GetLiveConfig.ashx the firmware requests from Live service 25.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openpak/x360-kdc/internal/config"
	"openpak/x360-kdc/internal/liveinfo"
)

func main() {
	cfg, err := config.LoadLiveInfo(os.Getenv)
	level := slog.LevelInfo
	if err == nil && cfg.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	h := &liveinfo.Handler{Hive: liveinfo.Hive{SMRevision: cfg.SMRevision, PollMinutes: cfg.PollMinutes, Extra: cfg.Extra}, Log: log}
	if _, err := h.Hive.Build(); err != nil {
		log.Error("hive", "err", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("x360-liveinfo listening", "addr", ln.Addr(), "smrevision", cfg.SMRevision, "poll_minutes", cfg.PollMinutes, "debug", cfg.Debug)
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

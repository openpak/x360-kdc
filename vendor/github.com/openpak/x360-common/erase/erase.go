// SPDX-License-Identifier: AGPL-3.0-only

// Package erase serves the account-erasure endpoint of card #120:
// DELETE /internal/accounts/{account_id}/data with the shared
// ACCOUNT_ERASE_KEY as bearer token. It listens on ERASE_ADDR (default
// ":9099") on the private container network only, and not at all while the
// key is unset.
package erase

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Func erases every row of one account and returns how many it removed.
// It must be idempotent.
type Func func(ctx context.Context, accountID string) (int, error)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidID reports whether id is a canonical UUID.
func ValidID(id string) bool { return uuidRE.MatchString(id) }

// Run executes fn for the account and writes the single "account erased" log line.
func Run(ctx context.Context, service, accountID string, fn Func) (int, error) {
	n, err := fn(ctx, accountID)
	if err != nil {
		return 0, err
	}
	slog.Info("account erased", "account", accountID, "rows", n, "service", service)
	return n, nil
}

// Handler serves the endpoint; key must not be empty.
func Handler(service, key string, fn Func) http.Handler {
	want := sha256.Sum256([]byte(key))
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /internal/accounts/{account_id}/data", func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(tok))
		if !ok || key == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("account_id")
		if !ValidID(id) {
			http.Error(w, "bad account id", http.StatusBadRequest)
			return
		}
		n, err := Run(r.Context(), service, id, fn)
		if err != nil {
			slog.Error("account erase failed", "service", service, "err", err.Error())
			http.Error(w, "erase failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"service": service, "rows": n})
	})
	return mux
}

// Serve starts the listener in the background when ACCOUNT_ERASE_KEY is set
// and stops it with ctx. Unset key: nothing is served.
func Serve(ctx context.Context, service string, fn Func) {
	key := os.Getenv("ACCOUNT_ERASE_KEY")
	if key == "" {
		slog.Info("account erase endpoint disabled", "service", service)
		return
	}
	addr := os.Getenv("ERASE_ADDR")
	if addr == "" {
		addr = ":9099"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("account erase listener", "service", service, "err", err.Error())
		return
	}
	srv := &http.Server{Handler: Handler(service, key, fn), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go srv.Serve(lis)
	go func() {
		<-ctx.Done()
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sd)
	}()
	slog.Info("account erase endpoint", "service", service, "addr", lis.Addr().String())
}

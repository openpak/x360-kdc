package xuacs

// Internal API for x360-kdc (the user AS exchange on the secondary host):
//
//	POST /internal/v1/user-key     {"console":"<12 digits>","gamertag":"<name, '_' for spaces>"}
//	  -> {"account","online_xuid","xenon_key"}   the profile 0x63F issued on that console
//	POST /internal/v1/wlid-ticket  {"ticket":"<std base64 of the padata 0xDA ticket>"}
//	  -> {"account","online_xuid","expires"}     a WLID access ticket this service signed
//
// Authenticated by X-Internal-Key; served on its own listener that is only
// published on the private (ZeroTier) address.

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// InternalKeyHeader carries the shared key.
const InternalKeyHeader = "X-Internal-Key"

// Internal returns the internal API handler; key must be non-empty.
func (h *Handler) Internal(key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get(InternalKeyHeader)), []byte(key)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Console  string `json:"console"`
			Gamertag string `json:"gamertag"`
			Ticket   string `json:"ticket"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		var out any
		var status int
		switch r.URL.Path {
		case "/internal/v1/user-key":
			out, status = h.userKey(r, in.Console, in.Gamertag)
		case "/internal/v1/wlid-ticket":
			out, status = h.wlidTicket(in.Ticket)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(out)
	})
}

type errBody struct {
	Error string `json:"error"`
}

// normTag compares gamertags the way the user AS-REQ cname renders them.
func normTag(s string) string { return strings.ToLower(strings.ReplaceAll(s, " ", "_")) }

func (h *Handler) userKey(r *http.Request, console, gamertag string) (any, int) {
	if consoleDigits(console+"@x") == "" || gamertag == "" {
		return errBody{"console and gamertag required"}, http.StatusBadRequest
	}
	profiles := h.Store.ConsoleProfiles(console)
	var hit *ConsoleProfile
	for i := range profiles {
		p := &profiles[i]
		tag := p.Gamertag
		if tag == "" { // record from before 0.8: the profile link's public code
			if l, err := h.Core.ActiveXboxLink(r.Context(), p.Account); err == nil && l != nil {
				tag = l.PublicCode
			}
		}
		if tag != "" && normTag(tag) == normTag(gamertag) {
			hit = p
			break
		}
	}
	log := h.log()
	if hit == nil {
		log.Info("internal user-key: no profile", "console", console, "gamertag", gamertag, "profiles", len(profiles))
		return errBody{"no profile with that gamertag on that console"}, http.StatusNotFound
	}
	log.Info("internal user-key", "console", console, "gamertag", gamertag, "account", hit.Account,
		"online", fmt.Sprintf("%016x", hit.Online))
	return struct {
		Account string `json:"account"`
		Online  string `json:"online_xuid"`
		Key     string `json:"xenon_key"`
	}{hit.Account, fmt.Sprintf("%016x", hit.Online), hex.EncodeToString(hit.Key)}, http.StatusOK
}

func (h *Handler) wlidTicket(b64 string) (any, int) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errBody{"base64"}, http.StatusBadRequest
	}
	t, err := h.VerifyWLIDTicket(raw)
	if err != nil {
		h.log().Info("internal wlid-ticket refused", "reason", err.Error(), "len", len(raw))
		return errBody{err.Error()}, http.StatusForbidden
	}
	return struct {
		Account string `json:"account"`
		Online  string `json:"online_xuid"`
		Expires string `json:"expires"`
	}{t.Account, fmt.Sprintf("%016x", t.XUID), t.Expires.UTC().Format(time.RFC3339)}, http.StatusOK
}

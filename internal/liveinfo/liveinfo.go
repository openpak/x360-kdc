// Package liveinfo serves the Xbox 360 LiveHive configuration: the HTTP GET
// /liveinfo/GetLiveConfig.ashx that xam.xex (firmware 17559) issues to Live
// service 25 right after the Live logon (XRL request 0x1300), and its sibling
// /liveinfo/getnetworkauthorizationlist.ashx (XRL request 0x1301).
//
// The body XAM accepts (parser FUN_8169a200, states 2 and 3) is NUL-terminated
// ASCII text "key=value;key=value;..." in which a literal '^' escapes the next
// character, with a total size below MaxBody bytes.
package liveinfo

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

const (
	// MaxBody is the exclusive upper bound on the body size XAM accepts.
	MaxBody = 0x7531

	// Poll frequency limits: XAM clamps LiveHivePollFrequencyInMinutes to
	// 30..240 and uses 120 when the key is absent.
	MinPollMinutes     = 30
	MaxPollMinutes     = 240
	DefaultPollMinutes = 120
)

// Hive is the set of keys the server publishes.
type Hive struct {
	// SMRevision is the hex string of the extended-system revision. When
	// present XAM requires it to equal the console's local revision (public
	// 17559 update: 126d69eb6cf3737c), otherwise it asks for a system update.
	// OpenPak policy: leave it empty (omitted) unless configured.
	SMRevision string
	// PollMinutes is LiveHivePollFrequencyInMinutes. Zero omits the key.
	PollMinutes int
	// Extra are further keys, emitted in order after the known ones. XAM
	// passes unknown keys through to the hive.
	Extra [][2]string
}

// ErrTooLarge is returned by Build when the body would not be accepted.
var ErrTooLarge = errors.New("liveinfo: body exceeds the size XAM accepts")

// escape prefixes the characters with a structural meaning with '^'.
func escape(s string) string {
	if !strings.ContainsAny(s, "^;=") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '^', ';', '=':
			b.WriteByte('^')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Build renders the hive text with its NUL terminator, or ErrTooLarge.
func (h Hive) Build() ([]byte, error) {
	var parts []string
	add := func(k, v string) { parts = append(parts, escape(k)+"="+escape(v)) }
	if h.SMRevision != "" {
		add("SMRevision", h.SMRevision)
	}
	if h.PollMinutes != 0 {
		add("LiveHivePollFrequencyInMinutes", strconv.Itoa(h.PollMinutes))
	}
	for _, kv := range h.Extra {
		add(kv[0], kv[1])
	}
	body := append([]byte(strings.Join(parts, ";")), 0)
	if len(body) >= MaxBody {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(body))
	}
	return body, nil
}

// Body is Build for callers that treat an oversized hive as a programming
// error: it returns nil when the hive is too large.
func (h Hive) Body() []byte {
	b, err := h.Build()
	if err != nil {
		return nil
	}
	return b
}

// Handler serves the two /liveinfo endpoints and logs every request, because
// the firmware's exact headers are still being established.
type Handler struct {
	Hive Hive
	Log  *slog.Logger
}

const (
	PathConfig  = "/liveinfo/GetLiveConfig.ashx"
	PathNetAuth = "/liveinfo/getnetworkauthorizationlist.ashx"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Log != nil {
		h.Log.Info("request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery,
			"user_agent", r.Header.Get("User-Agent"), "x_schema_ver", r.Header.Get("X-Schema-Ver"),
			"remote", r.RemoteAddr)
	}
	var body []byte
	switch strings.ToLower(r.URL.Path) {
	case strings.ToLower(PathConfig):
		var err error
		if body, err = h.Hive.Build(); err != nil {
			if h.Log != nil {
				h.Log.Error("hive", "err", err)
			}
			http.Error(w, "hive too large", http.StatusInternalServerError)
			return
		}
	case PathNetAuth:
		// Unverified: the format of the network authorization list is not
		// known yet, so answer with an empty hive (a lone NUL).
		body = []byte{0}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

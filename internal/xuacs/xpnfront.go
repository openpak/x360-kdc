package xuacs

import (
	"encoding/hex"
	"net/http"
	"strings"
)

// PathXPresence is Live service 1 (xpnfront), the presence/notification
// endpoint the console's XLive worker calls right after the service-26 stream
// is up. The request format is not decoded yet: the body is logged in full
// (presence data, no secrets) and answered with an empty 200 to see how the
// console reacts. ponytail: stopgap inside xuacs; own service once the format is known.
const PathXPresence = "/xpnfront/xpresence.srf"

func (h *Handler) xpresence(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if !strings.EqualFold(r.URL.Path, PathXPresence) {
		return false
	}
	h.log().Info("xpresence request", "account", r.Header.Get("X-X360-Account"), "users", r.Header.Get("X-X360-Users"),
		"body_len", len(body), "body_hex", hex.EncodeToString(body))
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	return true
}

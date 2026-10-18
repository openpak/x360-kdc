package xuacs

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// PathRevocation is Live service 21 (xbos licensing), request 0x918: after the
// user logon the console asks for the certificate revocation list, passing 16
// bytes of its key 0x42. The reply is a 256-byte signature, 16 bytes, and a
// u32 count of 20-byte revoked hashes (xrl-schema-opcodes.md in the Wharf
// notes); an empty, unsigned list is served. ponytail: stopgap inside xuacs; no
// signature check on the console side is assumed, add a real list if it objects.
const PathRevocation = "/xbos/GetRevocationList.ashx"

func (h *Handler) revocation(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if !strings.EqualFold(r.URL.Path, PathRevocation) {
		return false
	}
	out := make([]byte, 256+16+4)
	h.log().Info("revocation list request", "account", r.Header.Get("X-X360-Account"), "body_len", len(body), "body_hex", hex.EncodeToString(body))
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

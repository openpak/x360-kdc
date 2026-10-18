package xuacs

import (
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// PathXPresence is Live service 1 (xpnfront), the presence/notification
// endpoint the console's XLive worker calls right after the service-26 stream
// is up (xrl-schema-opcodes.md in the Wharf notes).
const PathXPresence = "/xpnfront/xpresence.srf"

// The console's request 0x2 ("presence alive", FUN_818d7568) carries one entry
// per signed-in user: a 32-byte header {u32 type 0x401, u32 msg_len, u32 seq,
// 20-byte network block} followed by msg_len bytes (0x79 + name length). The
// friend/block list versions the console holds sit at entry+0x66 / +0x6a.
// The reply is one element per entry: the header with msg_len 16 and the same
// seq, then u32 result | u32 friend-list version | u16 friend count | u32
// block-list version | u16 block count. Echoing the versions means "no change",
// zero counts mean empty lists; the console matches elements to users by seq
// and fails with 0x80150007 when none matches.
const (
	presenceHeader = 32
	presenceBody   = 16
)

// presenceAliveResponse builds the reply to a request-0x2 body, or nil when the
// body is not a whole number of well-formed entries.
func presenceAliveResponse(req []byte) []byte {
	var out []byte
	for len(req) > 0 {
		if len(req) < presenceHeader {
			return nil
		}
		n := presenceHeader + int(binary.LittleEndian.Uint32(req[4:]))
		if n < 0x70 || n > len(req) {
			return nil
		}
		e := req[:n]
		req = req[n:]
		h := append([]byte{}, e[:presenceHeader]...)
		binary.LittleEndian.PutUint32(h[4:], presenceBody)
		out = append(out, h...)
		out = binary.LittleEndian.AppendUint32(out, 0) // result
		out = append(out, e[0x66:0x6a]...)             // friend-list version
		out = binary.LittleEndian.AppendUint16(out, 0) // friend count
		out = append(out, e[0x6a:0x6e]...)             // block-list version
		out = binary.LittleEndian.AppendUint16(out, 0) // block count
	}
	return out
}

func (h *Handler) xpresence(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if !strings.EqualFold(r.URL.Path, PathXPresence) {
		return false
	}
	out := presenceAliveResponse(body)
	h.log().Info("xpresence request", "account", r.Header.Get("X-X360-Account"), "users", r.Header.Get("X-X360-Users"),
		"body_len", len(body), "body_hex", hex.EncodeToString(body), "reply_len", len(out))
	if out == nil {
		http.Error(w, "unsupported xpresence request", http.StatusBadRequest)
		return true
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

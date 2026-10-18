package xuacs

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// xstatsEmpty maps the xstats endpoints (Live services 34 "settings" and 35
// "titles/avatars", requests 0x707-0x716) to an empty-success reply: every
// count zero (xrlcodec build_response(id, {}) in the Wharf notes). The console's
// post-logon title sync calls these; a profile with nothing to sync is the
// truthful answer for now. ponytail: stopgap inside xuacs; real stats/achievement
// storage belongs in its own service.
var xstatsEmpty = map[string]string{
	"/xstats/syncsettings.ashx":           "000000000000000000000000",
	"/xstats/readsettings.ashx":           "0000",
	"/xstats/uploadconsoleauditlist.ashx": "",
	"/xstats/validateavatarmanifest.ashx": "00",
	"/xstats/synctitles.ashx":             "000000000000000000000000",
	"/xstats/enumtitles.ashx":             "0000",
	"/xstats/cleartitle.ashx":             "",
	"/xstats/syncachievements.ashx":       "000000000000000000000000",
	"/xstats/xachievementenum.ashx":       "0000",
	"/xstats/syncavatarassets.ashx":       "0000000000000000000000000000",
	"/xstats/xavatarassetenum.ashx":       "0000",
}

func (h *Handler) xstats(w http.ResponseWriter, r *http.Request, body []byte) bool {
	reply, ok := xstatsEmpty[strings.ToLower(r.URL.Path)]
	if !ok {
		return false
	}
	out, _ := hex.DecodeString(reply)
	h.log().Info("xstats request", "path", r.URL.Path, "account", r.Header.Get("X-X360-Account"), "body_len", len(body),
		"body_hex", hex.EncodeToString(body[:min(len(body), 256)]), "reply_len", len(out))
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

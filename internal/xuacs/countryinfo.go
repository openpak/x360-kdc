package xuacs

import (
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf16"
)

// CountryInfo download (Live service 11). After 0x627 the Account Recovery
// time-zone step runs DownloadCountryInfo: the applet fetches
// /xedl/ProfileInfo/<CountryId>/CountryInfo.cib from service 11 (AR
// lua_DownloadCountryInfo 0x90150730) and parses it with the CountryInfo
// reader (vtable 0x9010f94c slot 2, 0x9016dd98). Without service 11 in D7 the
// XMsg 0x58007 service lookup fails with 0x80151100, mapped to Win32 0x4DB,
// and the applet quits with "problem with the credentials" 800704DB.
//
// File layout, big-endian, strings UTF-16BE NUL-terminated (reader
// primitives 0x9016ca90 string, 0x9016d730 u16, 0x9016ca30 u32):
//
//	string            +0x04 (country code [guess])
//	string            +0x08 (country name [guess])
//	u16 (bool)        +0x0c
//	string            +0x10 date format (constructor default "mm/dd/yy")
//	string            +0x14 default time zone: a key of the applet's built-in
//	                        table (0x9017cb90: SAMOA, HAWAII, ALASKA, PACIFIC ...),
//	                        read by GetDefaultTimeZoneOfCountry
//	u16               +0x18 forbidden age, +0x1a minimum age, +0x1c parent age
//	u16 (bool) x2     +0x1e, +0x1f
//	u32 n + n x {string, string, u32, u32 language id}   locales (GetLocales)
//	u16 n + n x {u16, u16 bool, u16, u16, string x3, u16} (twice)
//	u16 n + n x {string, string}
//	u16 n + n x {u16}
//
// The applet only reads the default time zone on this path; the lists stay
// empty except one English locale.

// PathCountryInfoPrefix and PathCountryInfoSuffix bracket the country id.
const (
	PathCountryInfoPrefix = "/xedl/ProfileInfo/"
	PathCountryInfoSuffix = "/CountryInfo.cib"
)

// countryInfoID returns the country id of a CountryInfo path.
func countryInfoID(path string) (int, bool) {
	p := strings.ToLower(path)
	pre, suf := strings.ToLower(PathCountryInfoPrefix), strings.ToLower(PathCountryInfoSuffix)
	if !strings.HasPrefix(p, pre) || !strings.HasSuffix(p, suf) || len(p) <= len(pre)+len(suf) {
		return 0, false
	}
	id, err := strconv.Atoi(p[len(pre) : len(p)-len(suf)])
	return id, err == nil && id >= 0
}

func wstr(b []byte, s string) []byte {
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.BigEndian.AppendUint16(b, u)
	}
	return append(b, 0, 0)
}

// CountryInfo builds the CountryInfo.cib body. Every country gets the US
// settings [guess: OpenPak has no per-country data yet].
func CountryInfo() []byte {
	b := wstr(nil, "US")
	b = wstr(b, "United States")
	b = binary.BigEndian.AppendUint16(b, 1)  // +0x0c
	b = wstr(b, "mm/dd/yy")                  // date format (the constructor default)
	b = wstr(b, "PACIFIC")                   // default time zone
	b = binary.BigEndian.AppendUint16(b, 0)  // forbidden age
	b = binary.BigEndian.AppendUint16(b, 13) // minimum age
	b = binary.BigEndian.AppendUint16(b, 18) // parent age
	b = binary.BigEndian.AppendUint16(b, 0)  // +0x1e
	b = binary.BigEndian.AppendUint16(b, 0)  // +0x1f
	b = binary.BigEndian.AppendUint32(b, 1)  // locales
	b = wstr(b, "English")
	b = wstr(b, "en-US")
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 1) // XC_LANGUAGE_ENGLISH
	for i := 0; i < 4; i++ {                // the four u16-counted lists, empty
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	return b
}

func (h *Handler) serveCountryInfo(w http.ResponseWriter, r *http.Request, id int) {
	out := CountryInfo()
	h.log().Info("country info", "country_id", id, "body_len", len(out))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(out)
	}
}

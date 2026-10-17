package xuacs

import (
	"encoding/binary"
	"io"
	"net/http"
	"testing"
	"unicode/utf16"
)

// ciReader mirrors the applet's CountryInfo reader (0x9016dd98 and its list
// readers): big-endian u16/u32, UTF-16BE NUL-terminated strings.
type ciReader struct {
	b   []byte
	bad bool
}

func (r *ciReader) u16() int {
	if len(r.b) < 2 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return int(v)
}

func (r *ciReader) u32() int {
	if len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return int(v)
}

func (r *ciReader) str() string {
	var u []uint16
	for !r.bad {
		c := r.u16()
		if r.bad || c == 0 {
			break
		}
		u = append(u, uint16(c))
	}
	return string(utf16.Decode(u))
}

func TestCountryInfoLayout(t *testing.T) {
	r := &ciReader{b: CountryInfo()}
	code, name := r.str(), r.str()
	r.u16()
	r.str()
	tz := r.str()
	r.u16()
	minAge, parentAge := r.u16(), r.u16()
	r.u16()
	r.u16()
	for n := r.u32(); n > 0; n-- {
		r.str()
		r.str()
		r.u32()
		if lang := r.u32(); lang != 1 {
			t.Fatalf("language %d", lang)
		}
	}
	for k := 0; k < 2; k++ {
		for n := r.u16(); n > 0; n-- {
			r.u16()
			r.u16()
			r.u16()
			r.u16()
			r.str()
			r.str()
			r.str()
			r.u16()
		}
	}
	for n := r.u16(); n > 0; n-- {
		r.str()
		r.str()
	}
	for n := r.u16(); n > 0; n-- {
		r.u16()
	}
	if r.bad || len(r.b) != 0 {
		t.Fatalf("layout: bad=%v rest=%d", r.bad, len(r.b))
	}
	if code != "US" || name != "United States" || tz != "PACIFIC" || minAge != 13 || parentAge != 18 {
		t.Fatalf("fields %q %q %q %d %d", code, name, tz, minAge, parentAge)
	}
}

func TestCountryInfoServed(t *testing.T) {
	r := newRig(t, t.TempDir())
	for _, p := range []string{"/xedl/ProfileInfo/103/CountryInfo.cib", "/xedl/profileinfo/0/countryinfo.cib"} {
		resp, err := http.Get(r.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != string(CountryInfo()) {
			t.Fatalf("%s: %d %x", p, resp.StatusCode, b)
		}
	}
	for _, p := range []string{"/xedl/ProfileInfo/x/CountryInfo.cib", "/xedl/ProfileInfo//CountryInfo.cib"} {
		resp, err := http.Get(r.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
}

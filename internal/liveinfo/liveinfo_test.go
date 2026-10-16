package liveinfo

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyFormat(t *testing.T) {
	got := Hive{PollMinutes: 120}.Body()
	want := append([]byte("LiveHivePollFrequencyInMinutes=120"), 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("body %q", got)
	}
	got = Hive{SMRevision: "126d69eb6cf3737c", PollMinutes: 30, Extra: [][2]string{{"A", "b"}}}.Body()
	want = append([]byte("SMRevision=126d69eb6cf3737c;LiveHivePollFrequencyInMinutes=30;A=b"), 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("body %q", got)
	}
}

func TestEmptyHiveIsLoneNUL(t *testing.T) {
	if got := (Hive{}).Body(); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("empty hive %q", got)
	}
}

func TestEscaping(t *testing.T) {
	got := Hive{Extra: [][2]string{{"k", "a;b=c^d"}, {"x=y", "z"}}}.Body()
	want := append([]byte("k=a^;b^=c^^d;x^=y=z"), 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("body %q", got)
	}
}

func TestSizeLimit(t *testing.T) {
	// "k=" + value + NUL must stay below MaxBody.
	ok := Hive{Extra: [][2]string{{"k", strings.Repeat("a", MaxBody-1-3)}}}
	b, err := ok.Build()
	if err != nil || len(b) != MaxBody-1 {
		t.Fatalf("len %d err %v", len(b), err)
	}
	big := Hive{Extra: [][2]string{{"k", strings.Repeat("a", MaxBody-3)}}}
	if _, err := big.Build(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized accepted: %v", err)
	}
	if big.Body() != nil {
		t.Fatal("Body of oversized hive not nil")
	}
	// Escaping counts toward the limit.
	esc := Hive{Extra: [][2]string{{"k", strings.Repeat(";", MaxBody/2)}}}
	if _, err := esc.Build(); !errors.Is(err, ErrTooLarge) {
		t.Fatal("escaped growth ignored")
	}
}

func TestSMRevisionOmittedByDefault(t *testing.T) {
	h := Hive{PollMinutes: DefaultPollMinutes}
	if bytes.Contains(h.Body(), []byte("SMRevision")) {
		t.Fatal("SMRevision present by default")
	}
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", "xbox")
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	h := &Handler{Hive: Hive{PollMinutes: 120}}
	rec := get(h, PathConfig)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("config: %d %v", rec.Code, rec.Header())
	}
	if !bytes.Equal(rec.Body.Bytes(), h.Hive.Body()) || rec.Header().Get("Content-Length") != "35" {
		t.Fatalf("config body %q len %s", rec.Body.Bytes(), rec.Header().Get("Content-Length"))
	}
	rec = get(h, PathNetAuth)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), []byte{0}) || rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("netauth: %d %q", rec.Code, rec.Body.Bytes())
	}
	for _, p := range []string{"/", "/liveinfo/", "/liveinfo/other.ashx"} {
		if rec := get(h, p); rec.Code != 404 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}

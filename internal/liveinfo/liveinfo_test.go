package liveinfo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
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

func TestWireExactBytes(t *testing.T) {
	got, err := Hive{PollMinutes: 120}.Wire()
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x22, 0, 0, 0, 0x01, 0, 0x22, 0}, "LiveHivePollFrequencyInMinutes=120"...)
	if !bytes.Equal(got, want) || len(got) != 42 {
		t.Fatalf("wire %x", got)
	}
	const hexWant = "220000000100" + "2200" +
		"4c6976654869766550" + "6f6c6c4672657175656e6379496e4d696e75746573" + "3d313230"
	if hex.EncodeToString(got) != hexWant {
		t.Fatalf("wire hex %x", got)
	}
}

func TestWireEmptyAndLarge(t *testing.T) {
	if _, err := (Hive{}).Wire(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: %v", err)
	}
	big := Hive{Extra: [][2]string{{"k", strings.Repeat("a", 20000)}}}
	w, err := big.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.LittleEndian.Uint32(w); int(n) != 20002 || len(w) != 8+20002 {
		t.Fatalf("total %d len %d", n, len(w))
	}
	if binary.LittleEndian.Uint16(w[6:]) != 20002 {
		t.Fatal("chunk length")
	}
}

func post(h http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("User-Agent", "19/1.00.17559")
	req.Header.Set("Content-Type", "xon/19")
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	var logs bytes.Buffer
	h := &Handler{Hive: Hive{PollMinutes: 120}, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	rec := post(h, PathConfig, []byte{6, 0, 'x', 'e', 'n', 'o', 'n', 0})
	if rec.Code != 200 || rec.Header().Get("Content-Type") != ContentType {
		t.Fatalf("config: %d %v", rec.Code, rec.Header())
	}
	want, _ := h.Hive.Wire()
	if !bytes.Equal(rec.Body.Bytes(), want) || rec.Header().Get("Content-Length") != "42" {
		t.Fatalf("config body %x len %s", rec.Body.Bytes(), rec.Header().Get("Content-Length"))
	}
	if !strings.Contains(logs.String(), "body_hex=06007865") {
		t.Fatalf("request body not logged: %s", logs.String())
	}
	rec = get(h, PathNetAuth)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), []byte{0, 0}) || rec.Header().Get("Content-Type") != ContentType {
		t.Fatalf("netauth: %d %x", rec.Code, rec.Body.Bytes())
	}
	for _, p := range []string{"/", "/liveinfo/", "/liveinfo/other.ashx"} {
		if rec := get(h, p); rec.Code != 404 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}

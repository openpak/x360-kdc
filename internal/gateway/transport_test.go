package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// fakeClient drives a Gateway with an injected session, sealing client
// segments with the c2s keys and opening replies with the s2c keys.
type fakeClient struct {
	t        *testing.T
	g        *Gateway
	src      netip.AddrPort
	c2s, s2c dirKeys
	ctr      uint32
	cport    uint16
	seq, ack uint32 // next client seq, next expected server seq
}

func newFake(t *testing.T, upstream string) *fakeClient {
	c2s, s2c := testKeys(t)
	src := netip.MustParseAddrPort("10.0.0.5:3074")
	g := &Gateway{ServiceURL: upstream, Now: nil}
	g.sessions = map[netip.AddrPort]*Session{src: {Client: src, Account: "1@xbox.com", ClientSPI: []byte{0, 9, 8, 7},
		ServerSPI: []byte{0, 0xab, 0xc1, 0x23}, c2s: c2s, s2c: s2c, expires: g.now().Add(SessionTTL)}}
	return &fakeClient{t: t, g: g, src: src, c2s: c2s, s2c: s2c, cport: 0x7098, seq: 1000}
}

func (f *fakeClient) send(flags byte, seq, ack uint32, opts, payload []byte) []tcpSeg {
	f.t.Helper()
	f.ctr++
	off := byte(0x50)
	if len(opts) > 0 {
		off = 0x60
	}
	pkt := sealTCP(f.c2s, []byte{0, 0xab, 0xc1, 0x23}, f.ctr, tcpSeg{SrcPort: f.cport, DstPort: 80, Seq: seq, Ack: ack,
		Off: off, Flags: flags, Window: 0x4030, Options: opts, Payload: payload})
	var out []tcpSeg
	for _, r := range f.g.Handle(pkt, f.src) {
		sg, err := openTCP(f.s2c, r, 0)
		if err != nil {
			f.t.Fatalf("reply does not open: %v", err)
		}
		if !bytes.Equal(sg.SPI[1:], []byte{9, 8, 7}) || sg.SPI[0]&0x0f != 3 {
			f.t.Fatalf("reply SPI %x", sg.SPI)
		}
		out = append(out, sg)
	}
	return out
}

// SYN-ACK: built by the gateway, opened with the client-side key set.
func TestSynAck(t *testing.T) {
	f := newFake(t, "")
	r := f.send(flagSYN, 1000, 0, []byte(mssOption), nil)
	if len(r) != 1 {
		t.Fatalf("%d replies", len(r))
	}
	sg := r[0]
	if sg.Flags != 0x12 || sg.Off != 0x60 || sg.Ack != 1001 || sg.Window == 0 || string(sg.Options) != mssOption ||
		sg.SrcPort != 80 || sg.DstPort != 0x7098 || sg.SPI[0] != 0x83 {
		t.Fatalf("syn-ack: %+v", sg)
	}
	// a retransmitted SYN gets the same ISN
	if r2 := f.send(flagSYN, 1000, 0, []byte(mssOption), nil); len(r2) != 1 || r2[0].Seq != sg.Seq {
		t.Fatalf("SYN retransmit: %+v", r2)
	}
}

func TestServiceEndToEnd(t *testing.T) {
	big := strings.Repeat("0123456789", 300) // 3000 bytes: three response segments
	var gotHost, gotPath, gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, big)
	}))
	defer up.Close()
	f := newFake(t, up.URL)

	syn := f.send(flagSYN, 1000, 0, []byte(mssOption), nil)[0]
	iss := syn.Seq
	f.send(flagACK, 1001, iss+1, nil, nil) // handshake ACK: nothing to answer

	body := "hello"
	req := "POST /liveinfo/GetLiveConfig.ashx?x=1 HTTP/1.1\r\nHost: 1.2.3.4\r\nContent-Length: 5\r\nConnection: Keep-Alive\r\n\r\n" + body
	a, b := req[:60], req[60:]
	// out of order second half first: only an ACK of the old position comes back
	if r := f.send(flagACK|flagPSH, 1001+60, iss+1, nil, []byte(b)); len(r) != 1 || r[0].Ack != 1001 || len(r[0].Payload) != 0 {
		t.Fatalf("out-of-order: %+v", r)
	}
	r := f.send(flagACK, 1001, iss+1, nil, []byte(a))
	if len(r) < 2 {
		t.Fatalf("no response: %+v", r)
	}
	end := uint32(1001 + len(req))
	if r[0].Flags != flagACK || r[0].Ack != end || len(r[0].Payload) != 0 {
		t.Fatalf("data ack: %+v", r[0])
	}
	if gotHost != strings.TrimPrefix(up.URL, "http://") || gotPath != "/liveinfo/GetLiveConfig.ashx?x=1" || gotBody != body {
		t.Fatalf("upstream saw host %q path %q body %q", gotHost, gotPath, gotBody)
	}
	var resp []byte
	next := iss + 1
	for i, sg := range r[1:] {
		last := i == len(r)-2
		if sg.Seq != next {
			t.Fatalf("segment %d seq %d want %d", i, sg.Seq, next)
		}
		if sg.Ack != end {
			t.Fatalf("segment %d ack %d want %d", i, sg.Ack, end)
		}
		if last {
			if sg.Flags != flagFIN|flagACK || len(sg.Payload) != 0 {
				t.Fatalf("last segment %+v", sg)
			}
			next++
			continue
		}
		if len(sg.Payload) > respSegment {
			t.Fatalf("segment %d: %d bytes", i, len(sg.Payload))
		}
		wantPSH := i == len(r)-3
		if (sg.Flags&flagPSH != 0) != wantPSH || sg.Flags&flagACK == 0 {
			t.Fatalf("segment %d flags %#x", i, sg.Flags)
		}
		resp = append(resp, sg.Payload...)
		next += uint32(len(sg.Payload))
	}
	head, got, _ := strings.Cut(string(resp), "\r\n\r\n")
	if !strings.HasPrefix(head, "HTTP/1.1 200 OK\r\n") || !strings.Contains(head, "Content-Length: 3000") ||
		!strings.Contains(head, "Connection: close") || got != big || len(resp)%4 != 0 {
		t.Fatalf("response %q (%d bytes)", head, len(resp))
	}
	// client acks the data, then its FIN/ACK; connection is gone afterwards
	if r := f.send(flagACK, end, next-1, nil, nil); len(r) != 0 {
		t.Fatalf("ack of data answered: %+v", r)
	}
	r = f.send(flagFIN|flagACK, end, next, nil, nil)
	if len(r) != 1 || r[0].Flags != flagACK || r[0].Ack != end+1 {
		t.Fatalf("fin ack: %+v", r)
	}
	if n := len(f.g.sessions[f.src].conns); n != 0 {
		t.Fatalf("%d connections left", n)
	}
}

func TestDupAckRetransmitsAndReset(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 2500)) }))
	defer up.Close()
	f := newFake(t, up.URL)
	iss := f.send(flagSYN, 1000, 0, []byte(mssOption), nil)[0].Seq
	r := f.send(flagACK|flagPSH, 1001, iss+1, nil, []byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
	if len(r) < 3 {
		t.Fatalf("%d segments", len(r))
	}
	// the client acks only the first segment, then repeats it: go back to the hole
	end := uint32(1001 + 28)
	f.send(flagACK, end, iss+1+uint32(len(r[1].Payload)), nil, nil)
	rt := f.send(flagACK, end, iss+1+uint32(len(r[1].Payload)), nil, nil)
	if len(rt) == 0 || rt[0].Seq != iss+1+uint32(len(r[1].Payload)) {
		t.Fatalf("no retransmit from the hole: %+v", rt)
	}
	f.send(flagRST, end, 0, nil, nil)
	if len(f.g.sessions[f.src].conns) != 0 {
		t.Fatal("RST left the connection")
	}
}

func TestUpstreamDown(t *testing.T) {
	f := newFake(t, "http://127.0.0.1:1")
	iss := f.send(flagSYN, 1000, 0, []byte(mssOption), nil)[0].Seq
	r := f.send(flagACK|flagPSH, 1001, iss+1, nil, []byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
	if len(r) < 3 || !strings.HasPrefix(string(r[1].Payload), "HTTP/1.1 502 Bad Gateway\r\n") {
		t.Fatalf("%d segments", len(r))
	}
}

func TestSmallBodyHex(t *testing.T) {
	req := "POST /liveinfo/GetLiveConfig.ashx HTTP/1.0\r\nContent-Length: 8\r\n\r\n\x06\x00xenon\x00"
	if got := smallBodyHex([]byte(req)); got != "060078656e6f6e00" {
		t.Fatalf("got %q", got)
	}
	if got := smallBodyHex([]byte("GET / HTTP/1.0\r\n\r\n")); got != "" {
		t.Fatalf("no body: %q", got)
	}
	big := "POST / HTTP/1.0\r\nContent-Length: 65\r\n\r\n" + strings.Repeat("a", 65)
	if got := smallBodyHex([]byte(big)); got != "" {
		t.Fatalf("big: %q", got)
	}
}

func TestUserInfo0253(t *testing.T) {
	f := newFake(t, "")
	user := append([]byte{0x01 | 0x04 | 0x08}, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01) // flags, xuid LE
	user = append(user, 7, 0, 0, 0)                                                            // flag 1
	user = append(user, 2, 0xaa, 0xbb)                                                         // flag 4: len 2
	user = append(user, 9, 0, 0, 0)                                                            // flag 8
	for _, c := range []struct {
		name string
		body []byte
	}{{"keepalive", []byte{0, 0, 0, 0}}, {"user record", append([]byte{5, 0, 0, 0}, user...)}} {
		f.ctr += 4
		pkt := seal(f.c2s, []byte{0x80, 0xab, 0xc1, 0x23}, f.ctr, TypeUserInfo, c.body)
		out := f.g.Handle(pkt, f.src)
		if len(out) != 1 {
			t.Fatalf("%s: %d replies", c.name, len(out))
		}
		_, m, err := open(f.s2c, out[0])
		if err != nil || m.Type != 0x0953 || !bytes.Equal(m.Body, []byte{byte(f.ctr + 1), 0, 0, 0}) {
			t.Fatalf("%s: %+v %v", c.name, m, err)
		}
	}
	// truncated record: no reply, session kept
	f.ctr++
	if out := f.g.Handle(seal(f.c2s, []byte{0x80, 0xab, 0xc1, 0x23}, f.ctr, TypeUserInfo, []byte{0, 0, 0, 0, 1, 2}), f.src); out != nil {
		t.Fatal("truncated record answered")
	}
}

func TestServiceURLsRouteByPort(t *testing.T) {
	var hits [2]string
	var acct [2]string
	mk := func(i int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[i] = r.URL.Path
			acct[i] = r.Header.Get(AccountHeader)
			w.Write([]byte("ok"))
		}))
	}
	def, five := mk(0), mk(1)
	defer def.Close()
	defer five.Close()
	g := &Gateway{ServiceURL: def.URL, ServiceURLs: map[uint16]string{5: five.URL}}
	raw := []byte("POST /xuacs/x.ashx HTTP/1.0\r\nX-X360-Account: spoof\r\nContent-Length: 0\r\n\r\n")
	for _, port := range []uint16{5, 80, 25} {
		if st, _, _ := g.upstream(raw, port, "123@xbox.com", ""); st != "200 OK" {
			t.Fatalf("port %d: %s", port, st)
		}
	}
	if hits[1] == "" || hits[0] == "" || acct[1] != "123@xbox.com" {
		t.Fatalf("routing: default %q five %q account %q", hits[0], hits[1], acct[1])
	}
	hits = [2]string{}
	g.upstream(raw, 5, "", "")
	if hits[0] != "" || hits[1] == "" || acct[1] != "" {
		t.Fatalf("port 5 went to default or kept a spoofed account %q", acct[1])
	}
	g2 := &Gateway{ServiceURLs: map[uint16]string{5: five.URL}}
	if st, _, _ := g2.upstream(raw, 80, "", ""); st != "503 Service Unavailable" {
		t.Fatalf("unrouted port without default: %s", st)
	}
}

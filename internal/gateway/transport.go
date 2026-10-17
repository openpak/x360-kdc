package gateway

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openpak/x360-kdc/internal/kdc"
)

// Service transport: XAM runs a TCP connection inside the secure channel
// (svc-open-layout.md). The gateway is the passive end: SYN -> SYN-ACK, the
// client's HTTP request is reassembled from its data segments and proxied to
// the service backend, and the response goes back as data segments followed by
// a FIN. All state lives in the Session, under the Gateway mutex.

const (
	respSegment = 1200 // payload bytes per server segment (client MSS is 1264)
	svcWindow   = 0x4030
	maxRequest  = 64 << 10
	maxResponse = 4 << 20
)

// AccountHeader carries the session's console account to the service backend.
const AccountHeader = "X-X360-Account"

// UsersHeader lists the users signed in on the tunnel's ticket as
// "<online xuid hex>:<OpenPak account id>" separated by commas.
const UsersHeader = "X-X360-Users"

func usersHeader(users []kdc.TicketUser) string {
	var parts []string
	for _, u := range users {
		parts = append(parts, fmt.Sprintf("%016x:%s", u.XUID, u.Account))
	}
	return strings.Join(parts, ",")
}

type tcpKey struct{ client, server uint16 }

type tcpConn struct {
	key                    tcpKey
	iss, irs               uint32
	sndUna, sndNxt, rcvNxt uint32
	peerWindow             uint16
	established            bool
	req                    []byte
	ooo                    map[uint32][]byte
	clientFin              bool
	responded              bool
	resp                   []byte // response bytes; stream offset 0 is sequence iss+1
	finQueued              bool
}

func (c *tcpConn) respEnd() uint32 { // stream offsets, FIN counted as one
	n := uint32(len(c.resp))
	if c.finQueued {
		n++
	}
	return n
}

// tcpSegment handles one verified client segment and returns the datagrams to send.
func (g *Gateway) tcpSegment(s *Session, sg tcpSeg, now time.Time) [][]byte {
	log := g.log().With("src", s.Client, "account", s.Account)
	log.Info("tcp rx", "ports", fmt.Sprintf("%d>%d", sg.SrcPort, sg.DstPort), "flags", fmt.Sprintf("%#02x", sg.Flags),
		"seq", sg.Seq, "ack", sg.Ack, "win", sg.Window, "len", len(sg.Payload), "ctr", sg.Counter)
	if s.conns == nil {
		s.conns = map[tcpKey]*tcpConn{}
	}
	key := tcpKey{sg.SrcPort, sg.DstPort}
	c := s.conns[key]
	var out [][]byte
	emit := func(flags byte, seq, ack uint32, opts, payload []byte) {
		s.sendCtr++
		sg := tcpSeg{SrcPort: key.server, DstPort: key.client, Seq: seq, Ack: ack, Off: 0x50, Flags: flags,
			Window: svcWindow, Options: opts, Payload: payload}
		if len(opts) > 0 {
			sg.Off = 0x60
		}
		out = append(out, sealTCP(s.s2c, s.ClientSPI, s.sendCtr, sg))
		log.Info("tcp tx", "ports", fmt.Sprintf("%d>%d", key.server, key.client), "flags", fmt.Sprintf("%#02x", flags),
			"seq", seq, "ack", ack, "len", len(payload), "ctr", s.sendCtr)
	}
	if sg.Flags&flagRST != 0 {
		if c != nil {
			delete(s.conns, key)
			log.Info("tcp reset by client", "ports", key)
		}
		return nil
	}
	if sg.Flags&flagSYN != 0 && sg.Flags&flagACK == 0 {
		if c == nil || c.irs != sg.Seq {
			var b [4]byte
			rand.Read(b[:])
			iss := binary.BigEndian.Uint32(b[:])
			c = &tcpConn{key: key, iss: iss, irs: sg.Seq, sndUna: iss, sndNxt: iss + 1, rcvNxt: sg.Seq + 1}
			s.conns[key] = c
		}
		c.peerWindow = sg.Window
		emit(flagSYN|flagACK, c.iss, c.rcvNxt, []byte(mssOption), nil)
		return out
	}
	if c == nil {
		if len(sg.Payload) > 0 || sg.Flags&flagFIN != 0 {
			log.Info("tcp segment without connection, reset", "ports", key)
			emit(flagRST, sg.Ack, 0, nil, nil)
		}
		return out
	}
	// ACK processing.
	dupAck := false
	if sg.Flags&flagACK != 0 {
		if !between(c.sndUna, sg.Ack, c.sndNxt) {
			log.Info("tcp ack out of range", "ack", sg.Ack, "una", c.sndUna, "nxt", c.sndNxt)
		} else if sg.Ack == c.sndUna {
			dupAck = c.sndNxt != c.sndUna && len(sg.Payload) == 0 && sg.Flags&flagFIN == 0
		} else {
			c.sndUna = sg.Ack
		}
		if !c.established && sg.Ack == c.iss+1 {
			c.established = true
			log.Info("tcp established", "ports", key)
		}
		c.peerWindow = sg.Window
	}
	// Data and FIN.
	needAck := false
	if n := uint32(len(sg.Payload)); n > 0 {
		needAck = true
		seq, p := sg.Seq, sg.Payload
		if seq-c.rcvNxt > 1<<31 { // starts before rcvNxt: trim the part already received
			cut := c.rcvNxt - seq
			if cut >= n {
				p = nil
			} else {
				p, seq = p[cut:], c.rcvNxt
			}
		}
		if len(p) > 0 && seq == c.rcvNxt {
			c.req = append(c.req, p...)
			c.rcvNxt += uint32(len(p))
			for q, ok := c.ooo[c.rcvNxt]; ok; q, ok = c.ooo[c.rcvNxt] {
				delete(c.ooo, c.rcvNxt)
				c.req = append(c.req, q...)
				c.rcvNxt += uint32(len(q))
			}
		} else if len(p) > 0 && seq-c.rcvNxt < 1<<16 {
			if c.ooo == nil {
				c.ooo = map[uint32][]byte{}
			}
			c.ooo[seq] = append([]byte{}, p...)
		}
	}
	if sg.Flags&flagFIN != 0 && sg.Seq+uint32(len(sg.Payload)) == c.rcvNxt && !c.clientFin {
		c.clientFin = true
		c.rcvNxt++
		needAck = true
	} else if sg.Flags&flagFIN != 0 {
		needAck = true
	}
	if len(c.req) > maxRequest {
		log.Info("tcp request too large, reset", "ports", key)
		emit(flagRST, c.sndNxt, 0, nil, nil)
		delete(s.conns, key)
		return out
	}
	if !c.responded && requestComplete(c.req) {
		c.responded = true
		c.resp = g.serve(c.req, key.server, s.Account, usersHeader(s.Users), log)
		c.finQueued = true
	}
	if needAck {
		emit(flagACK, c.sndNxt, c.rcvNxt, nil, nil)
	}
	// Send response data (and FIN) within the peer's window; on a duplicate
	// ACK or a repeated segment go back to the first unacknowledged byte.
	win := uint32(max(int(c.peerWindow), respSegment))
	from := c.sndNxt
	if dupAck || (needAck && len(sg.Payload) > 0 && c.sndNxt != c.sndUna) {
		from = c.sndUna
		log.Info("tcp retransmit", "from", from-c.iss-1)
	}
	limit := c.sndUna + win
	for from != c.iss+1+c.respEnd() && from-c.sndUna < win && c.responded {
		off := from - c.iss - 1
		n := uint32(len(c.resp))
		if off >= n { // FIN
			emit(flagFIN|flagACK, from, c.rcvNxt, nil, nil)
			from++
		} else {
			l := min(uint32(respSegment), n-off, limit-from)
			fl := byte(flagACK)
			if off+l == n {
				fl |= flagPSH
			}
			emit(fl, from, c.rcvNxt, nil, c.resp[off:off+l])
			from += l
		}
		if from-c.sndUna > c.sndNxt-c.sndUna {
			c.sndNxt = from
		}
	}
	if c.responded && c.clientFin && c.sndUna == c.iss+1+c.respEnd() {
		log.Info("tcp closed", "ports", key, "request_bytes", len(c.req), "response_bytes", len(c.resp))
		delete(s.conns, key)
	}
	return out
}

// between reports lo <= v <= hi in sequence space.
func between(lo, v, hi uint32) bool { return v-lo <= hi-lo }

// requestComplete reports whether buf holds a full HTTP request (headers plus
// Content-Length body).
func requestComplete(buf []byte) bool {
	i := bytes.Index(buf, []byte("\r\n\r\n"))
	if i < 0 {
		return false
	}
	need := 0
	for _, l := range strings.Split(string(buf[:i]), "\r\n")[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			need, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return len(buf) >= i+4+need
}

// smallBodyHex returns the request body as hex when Content-Length is 1..64
// (the XRL request bodies are tiny; this captures them), else "".
func smallBodyHex(raw []byte) string {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return ""
	}
	n := -1
	for _, l := range strings.Split(string(raw[:i]), "\r\n")[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	body := raw[i+4:]
	if n < 1 || n > 64 || len(body) < n {
		return ""
	}
	return hex.EncodeToString(body[:n])
}

// serve proxies the raw HTTP request to the service backend and returns the
// raw HTTP response (always well formed, 502/503 when the backend is not reachable).
func (g *Gateway) serve(raw []byte, port uint16, account, users string, log interface{ Info(string, ...any) }) []byte {
	reqLine, _, _ := strings.Cut(string(raw), "\r\n")
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	log.Info("http request", "port", port, "line", reqLine, "headers", strings.ReplaceAll(head, "\r\n", " | "), "bytes", len(raw),
		"body_hex", smallBodyHex(raw))
	status, hdr, body := g.upstream(raw, port, account, users)
	resp := buildResponse(status, hdr, body)
	log.Info("http response", "status", status, "body_len", len(body), "bytes", len(resp))
	return resp
}

func (g *Gateway) upstream(raw []byte, port uint16, account, users string) (string, http.Header, []byte) {
	fail := func(status string, err error) (string, http.Header, []byte) {
		g.log().Info("service backend failed", "status", status, "err", err.Error())
		return status, http.Header{"Content-Type": {"text/plain"}}, []byte(status + "\n")
	}
	target := g.serviceURL(port)
	if target == "" {
		return fail("503 Service Unavailable", fmt.Errorf("no service URL configured for port %d", port))
	}
	base, err := url.Parse(target)
	if err != nil {
		return fail("503 Service Unavailable", err)
	}
	req, err := http.ReadRequest(bufioReader(raw))
	if err != nil {
		return fail("400 Bad Request", err)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequest))
	if err != nil {
		return fail("400 Bad Request", err)
	}
	out, err := http.NewRequest(req.Method, strings.TrimRight(base.String(), "/")+req.RequestURI, bytes.NewReader(body))
	if err != nil {
		return fail("400 Bad Request", err)
	}
	for k, v := range req.Header {
		out.Header[k] = v
	}
	for _, h := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Content-Length", "Transfer-Encoding"} {
		out.Header.Del(h)
	}
	// The tunnel's authenticated console ("<digits>@xbox.com"), for backends
	// that need to know it (xuacs enrolment). A client-sent value is replaced.
	out.Header.Del(AccountHeader)
	out.Header.Del(UsersHeader)
	if account != "" {
		out.Header.Set(AccountHeader, account)
	}
	if users != "" {
		out.Header.Set(UsersHeader, users)
	}
	out.Host = base.Host
	cl := g.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := cl.Do(out)
	if err != nil {
		return fail("502 Bad Gateway", err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fail("502 Bad Gateway", err)
	}
	return resp.Status, resp.Header, rb
}

// buildResponse renders HTTP/1.1 with Content-Length and Connection: close.
// The total length is kept a multiple of 4 (an X-Pad header when needed) so
// every 1200-byte segment, the last included, has a pad of 0 or 4 and the
// ICV input needs no filler.
func buildResponse(status string, hdr http.Header, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	hdr.WriteSubset(&b, map[string]bool{"Connection": true, "Content-Length": true, "Transfer-Encoding": true,
		"Keep-Alive": true, "Proxy-Connection": true, "Upgrade": true, "Trailer": true})
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n")
	total := b.Len() + 2 + len(body)
	if k := -total & 3; k != 0 {
		b.WriteString("X-Pad: " + strings.Repeat("0", (k+3)&3) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func bufioReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

// serviceURL is the backend for a tunnelled connection to the given service
// port: the ServiceURLs entry, else the ServiceURL default.
func (g *Gateway) serviceURL(port uint16) string {
	if u, ok := g.ServiceURLs[port]; ok && u != "" {
		return u
	}
	return g.ServiceURL
}

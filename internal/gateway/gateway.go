// Package gateway is OpenPak's Xbox 360 security gateway on UDP 3074: the
// SG initiation handshake the firmware (XAM 17559) runs after the XETGS
// sg/S0 ticket, and the secure-channel data packets that follow.
//
// Everything mirrors the clean-room oracle scratch/wharf/kdcstub/sg.py and
// sg_data_check.py (docs/xbox360/wharf-base-plan.md, section "security
// gateway (UDP 3074) handshake, secure-channel data packets"). Any datagram
// that fails a check is dropped without a reply and logged with the reason;
// logs never carry key material.
package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"openpak/x360-kdc/internal/kdc"
)

// Message types the gateway itself acts on.
const (
	TypeClose     = 0x0053 // client closes the session; no reply
	TypeAck       = 0x0153 // empty acknowledgement
	TypeChallenge = 0x0A53 // challenge result; any authenticated reply moves XAM's gateway state 5 -> 6
)

// SessionTTL is the idle lifetime of a session: the 300 in the reply core,
// in the firmware's 5-second units.
const SessionTTL = lifetimeA * 5 * time.Second

// Message is a decrypted secure-channel message.
type Message struct {
	Type    uint16
	Counter uint32
	Body    []byte
}

// Handler answers one message of a given type. It returns the messages to
// send back (each is sealed with the next server-to-client counter). This is
// the extension point for per-type handling: the service-25 tunnel and the
// other client messages (0x0B53, 0x0253, 0x0553, ...) plug in here.
type Handler func(s *Session, m Message) ([]Message, error)

// Session is one authenticated client.
type Session struct {
	Client    netip.AddrPort
	Account   string // "<digits>@xbox.com"
	ClientSPI []byte // carried by server-to-client packets
	ServerSPI []byte // first byte 0; the client sends it with 0x80 ORed into the first byte
	c2s, s2c  dirKeys
	sendCtr   uint32 // last server-to-client counter used; starts at 0, first packet is 1
	lastRecv  uint32
	expires   time.Time
}

// Gateway is the protocol as a function from datagram to replies.
type Gateway struct {
	TicketKey    []byte         // the KDC's ticket key, 16 bytes
	AccountsPath string         // the KDC's account store, re-read on every initiation
	CA           *rsa.PublicKey // console CA: stored certificates must still verify
	Now          func() time.Time
	Log          *slog.Logger
	Rand         io.Reader // default crypto/rand
	// Handlers maps a message type to its handler; nil uses DefaultHandlers.
	Handlers map[uint16]Handler

	mu       sync.Mutex
	sessions map[netip.AddrPort]*Session
}

// DefaultHandlers is what the oracle does: 0x0A53 is answered with an empty
// 0x0153. Unknown types are logged by Handle and the session is kept.
func DefaultHandlers() map[uint16]Handler {
	return map[uint16]Handler{
		TypeChallenge: func(*Session, Message) ([]Message, error) { return []Message{{Type: TypeAck}}, nil },
	}
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) rnd() io.Reader {
	if g.Rand != nil {
		return g.Rand
	}
	return rand.Reader
}

func (g *Gateway) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Sessions is the number of live sessions.
func (g *Gateway) Sessions() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

// Handle processes one datagram and returns the datagrams to send back to
// src (none on rejection or for messages that need no answer).
func (g *Gateway) Handle(data []byte, src netip.AddrPort) [][]byte {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, s := range g.sessions {
		if now.After(s.expires) {
			g.log().Info("session expired", "src", k, "account", s.Account)
			delete(g.sessions, k)
		}
	}
	var out [][]byte
	var err error
	kind := "data"
	if len(data) >= 4 && [4]byte(data[:4]) == [4]byte{} {
		kind = "initiation"
		var reply []byte
		reply, err = g.initiate(data, src, now)
		if reply != nil {
			out = [][]byte{reply}
		}
	} else {
		out, err = g.data(data, src, now)
	}
	if err != nil {
		g.log().Info("rejected", "kind", kind, "src", src, "len", len(data), "err", err.Error())
	}
	return out
}

func (g *Gateway) initiate(data []byte, src netip.AddrPort, now time.Time) ([]byte, error) {
	in, err := parseInitiation(data)
	if err != nil {
		return nil, err
	}
	accounts, err := kdc.OpenStore(g.AccountsPath) // read-only; refreshes accounts the KDC issued meanwhile
	if err != nil {
		return nil, fmt.Errorf("accounts: %w", err)
	}
	v, err := verify(in, g.TicketKey, accounts, g.CA, now)
	if err != nil {
		return nil, err
	}
	p, err := g.newParams()
	if err != nil {
		return nil, err
	}
	reply, material, err := in.reply(v, src.Addr(), p)
	if err != nil {
		return nil, err
	}
	c2s, s2c := derive(material)
	if g.sessions == nil {
		g.sessions = map[netip.AddrPort]*Session{}
	}
	g.sessions[src] = &Session{Client: src, Account: v.name, ClientSPI: append([]byte{}, in.clientSPI...),
		ServerSPI: p.spi, c2s: c2s, s2c: s2c, expires: now.Add(SessionTTL)}
	g.log().Info("authenticated", "src", src, "account", v.name, "chunks", fmt.Sprintf("%#x", in.chunks),
		"client_spi", hex.EncodeToString(in.clientSPI), "server_spi", hex.EncodeToString(p.spi),
		"len", len(data), "reply_len", len(reply))
	return reply, nil
}

// newParams draws the DH private (96 random bytes LE), the server nonce and
// a server SPI (0 + 3 random bytes, non-zero, unique among live sessions).
func (g *Gateway) newParams() (replyParams, error) {
	var p replyParams
	buf := make([]byte, dhLen+8+3)
	for {
		if _, err := io.ReadFull(g.rnd(), buf); err != nil {
			return p, err
		}
		p = replyParams{private: leInt(buf[:dhLen]), snonce: buf[dhLen : dhLen+8], spi: append([]byte{0}, buf[dhLen+8:]...)}
		if p.private.Sign() > 0 && !g.spiInUse(p.spi) && [3]byte(p.spi[1:]) != [3]byte{} {
			return p, nil
		}
	}
}

func (g *Gateway) spiInUse(spi []byte) bool {
	for _, s := range g.sessions {
		if string(s.ServerSPI) == string(spi) {
			return true
		}
	}
	return false
}

func (g *Gateway) data(pkt []byte, src netip.AddrPort, now time.Time) ([][]byte, error) {
	s := g.sessions[src]
	if s == nil {
		return nil, errors.New("data before SG authentication")
	}
	spi, m, err := open(s.c2s, pkt)
	if err != nil {
		// The datagram is ciphertext; keeping it lets an undecodable shape be studied offline.
		g.log().Info("unverifiable data", "src", src, "account", s.Account, "len", len(pkt), "hex", hex.EncodeToString(pkt))
		return nil, err
	}
	// The client puts 0x80 into the first SPI byte on its first data packet.
	if spi[0]&0x7f != s.ServerSPI[0] || string(spi[1:]) != string(s.ServerSPI[1:]) {
		return nil, fmt.Errorf("data SPI %x is not this session's", spi)
	}
	s.expires = now.Add(SessionTTL)
	replay := m.Counter != 0 && m.Counter <= s.lastRecv
	if m.Counter > s.lastRecv {
		s.lastRecv = m.Counter
	}
	g.log().Info("data", "src", src, "account", s.Account, "type", fmt.Sprintf("%#06x", m.Type), "ctr", m.Counter,
		"replay", replay, "body_len", len(m.Body), "body", hex.EncodeToString(m.Body))
	if m.Type == TypeClose {
		delete(g.sessions, src)
		g.log().Info("session closed", "src", src, "account", s.Account)
		return nil, nil
	}
	handlers := g.Handlers
	if handlers == nil {
		handlers = DefaultHandlers()
	}
	h := handlers[m.Type]
	if h == nil {
		g.log().Info("unhandled message type, session kept", "src", src, "type", fmt.Sprintf("%#06x", m.Type))
		return nil, nil
	}
	replies, err := h(s, Message{Type: m.Type, Counter: m.Counter, Body: m.Body})
	if err != nil {
		return nil, fmt.Errorf("handler %#06x: %w", m.Type, err)
	}
	var out [][]byte
	for _, r := range replies {
		s.sendCtr++
		out = append(out, seal(s.s2c, s.ClientSPI, s.sendCtr, r.Type, r.Body))
		g.log().Info("data reply", "src", src, "type", fmt.Sprintf("%#06x", r.Type), "ctr", s.sendCtr, "body_len", len(r.Body))
	}
	return out, nil
}

package gateway

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
)

// The first message the console sent on service 26 (captured 2026-10-18).
const streamHello = "0100000064000000851d00000100000022000000000000000100dbda39515f000900"

func TestStreamCommand100(t *testing.T) {
	g := &Gateway{}
	log := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
	msg, _ := hex.DecodeString(streamHello)
	c := &tcpConn{req: msg[:20]}
	g.streamServe(c, log)
	if len(c.resp) != 0 || len(c.req) != 20 {
		t.Fatal("partial message must wait")
	}
	c.req = msg
	g.streamServe(c, log)
	r := c.resp
	if len(r) != 28 || binary.LittleEndian.Uint32(r[4:]) != 301 || !bytes.Equal(r[8:12], msg[8:12]) ||
		binary.LittleEndian.Uint32(r[16:]) != 28 || binary.LittleEndian.Uint32(r[24:]) != 0 || len(c.req) != 0 {
		t.Fatalf("reply %x, left %d", r, len(c.req))
	}
}

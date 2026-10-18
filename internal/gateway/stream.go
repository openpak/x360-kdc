package gateway

import (
	"encoding/binary"
	"encoding/hex"
)

// streamPort is Live service 26, a long-lived TCP stream the console's XLive
// worker opens after the user logon (FUN_818f07a8, state machine FUN_818d02b8).
const streamPort = 26

// Messages are little-endian: u16 version | u16 0 | u32 command | u32 request
// id | u32 flags | u32 total length | u32 retry count | body. The console's
// first message is command 100 (body: u16 1 | online XUID); the state machine
// accepts command+201 with the same id and a 4-byte status after the header
// (0 = success). Commands 101..105 expect other shapes and are only logged.
const streamHeader = 24

// streamServe consumes whole messages from c.req and appends the replies to
// c.resp (no FIN: the stream stays open for the console's later messages).
func (g *Gateway) streamServe(c *tcpConn, log interface{ Info(string, ...any) }) {
	for len(c.req) >= streamHeader {
		total := int(binary.LittleEndian.Uint32(c.req[16:]))
		if total < streamHeader || total > maxRequest {
			c.req = nil
			return
		}
		if len(c.req) < total {
			return
		}
		msg := c.req[:total]
		c.req = c.req[total:]
		cmd := binary.LittleEndian.Uint32(msg[4:])
		log.Info("stream message", "cmd", cmd, "id", binary.LittleEndian.Uint32(msg[8:]), "len", total, "hex", hex.EncodeToString(msg))
		if cmd != 100 {
			continue
		}
		reply := make([]byte, streamHeader+4)
		copy(reply, msg[:streamHeader])
		binary.LittleEndian.PutUint32(reply[4:], cmd+201)
		binary.LittleEndian.PutUint32(reply[16:], uint32(len(reply)))
		c.resp = append(c.resp, reply...)
		c.responded = true
	}
}

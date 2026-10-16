package gateway

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// TCP inside the secure channel (code 3 datagrams, port mode "u16 each"), per
// scratch/wharf/kdcstub/notes/svc-open-layout.md:
//
//	SPI(4) | 3DES-CBC(options+payload | run[:pad]) | run[pad:] | ctr low16 LE | ICV10
//
// where the run is ports(4: src, dst, big-endian) | seq(4) ack(4) off(1)
// flags(1) window(2), SPI byte 0 = pad<<5 | 3. The ICV covers
// run[pad:] || ctr_lo16 || ctr_hi16 || SPI first, then the ciphertext.
//
// The ICV input in front of the ciphertext is rounded up to a multiple of 4
// with zero bytes ((16-pad+8+3)&~3 in the firmware). That is exact for pad 0
// and 4 (the SYN, ACKs and any segment whose length is a multiple of 4); for
// other pads the filler bytes are an assumption, untested against hardware.

const (
	codeTCP16 = 3 // SPI byte 0 low bits: TCP, both ports as u16

	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10

	mssOption = "\x02\x04\x04\xf0" // MSS 1264
)

// tcpSeg is one decoded TCP-over-SA segment.
type tcpSeg struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Off, Flags       byte
	Window           uint16
	Options, Payload []byte
	Counter          uint32
	SPI              []byte
}

func tcpMAC(hk, plain, spi []byte, counter uint32, ct []byte) []byte {
	h := hmac.New(sha1.New, hk)
	in1 := append([]byte{}, plain...)
	in1 = binary.LittleEndian.AppendUint16(in1, uint16(counter))
	in1 = binary.LittleEndian.AppendUint16(in1, uint16(counter>>16))
	in1 = append(in1, spi...)
	in1 = append(in1, make([]byte, -len(in1)&3)...)
	h.Write(in1)
	h.Write(ct)
	return h.Sum(nil)[:10]
}

// isTCP reports whether the datagram is a code 1..3 (TCP) data packet.
func isTCP(pkt []byte) bool {
	return len(pkt) >= 4 && pkt[0]&0x0f >= 1 && pkt[0]&0x0f <= 3
}

// sealTCP builds one code-3 datagram. spi is the 4-byte SPI; its first byte
// is replaced by pad<<5|3. opts are TCP options (a multiple of 4 bytes).
func sealTCP(d dirKeys, spi []byte, counter uint32, sg tcpSeg) []byte {
	body := append(append([]byte{}, sg.Options...), sg.Payload...)
	pad := -len(body) & 7
	run := binary.BigEndian.AppendUint16(nil, sg.SrcPort)
	run = binary.BigEndian.AppendUint16(run, sg.DstPort)
	run = binary.BigEndian.AppendUint32(run, sg.Seq)
	run = binary.BigEndian.AppendUint32(run, sg.Ack)
	run = append(run, sg.Off, sg.Flags)
	run = binary.BigEndian.AppendUint16(run, sg.Window)
	pt := append(body, run[:pad]...)
	ct, err := cbc(d.k, ivFor(d.seed, counter), pt, true)
	if err != nil {
		panic(err)
	}
	wspi := append([]byte{byte(pad<<5) | codeTCP16}, spi[1:4]...)
	pkt := append(append([]byte{}, wspi...), ct...)
	pkt = append(pkt, run[pad:]...)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(counter))
	return append(pkt, tcpMAC(d.hk, run[pad:], wspi, counter, ct)...)
}

// openTCP verifies and decodes a code-3 datagram. hi is the assumed high 16
// bits of the sender's 32-bit counter.
func openTCP(d dirKeys, pkt []byte, hi uint16) (tcpSeg, error) {
	var sg tcpSeg
	if len(pkt) < 4+16+12-7 || pkt[0]&0x0f != codeTCP16 {
		return sg, fmt.Errorf("not a code-3 packet (%d bytes, byte0 %#x)", len(pkt), pkt[0])
	}
	pad := int(pkt[0]>>5) & 7
	n := len(pkt)
	plainLen := 16 - pad
	e := n - 4 - plainLen - 12
	if e < 0 || e%8 != 0 || pad > e {
		return sg, fmt.Errorf("code-3 length %d with pad %d", n, pad)
	}
	spi, ct := pkt[:4], pkt[4:4+e]
	plain := pkt[4+e : 4+e+plainLen]
	lo := binary.LittleEndian.Uint16(pkt[n-12:])
	ctr := uint32(hi)<<16 | uint32(lo)
	if !hmac.Equal(pkt[n-10:], tcpMAC(d.hk, plain, spi, ctr, ct)) {
		return sg, errors.New("code-3 ICV mismatch")
	}
	var dec []byte
	if e > 0 {
		var err error
		if dec, err = cbc(d.k, ivFor(d.seed, ctr), ct, false); err != nil {
			return sg, err
		}
	}
	run := append(append([]byte{}, dec[e-pad:]...), plain...)
	sg.SrcPort = binary.BigEndian.Uint16(run[0:])
	sg.DstPort = binary.BigEndian.Uint16(run[2:])
	sg.Seq = binary.BigEndian.Uint32(run[4:])
	sg.Ack = binary.BigEndian.Uint32(run[8:])
	sg.Off, sg.Flags = run[12], run[13]
	sg.Window = binary.BigEndian.Uint16(run[14:])
	sg.Counter, sg.SPI = ctr, spi
	body := dec[:e-pad]
	opt := int(sg.Off>>4)*4 - 20
	if opt < 0 || opt > len(body) {
		return sg, fmt.Errorf("code-3 data offset %#x with %d body bytes", sg.Off, len(body))
	}
	sg.Options, sg.Payload = body[:opt], body[opt:]
	return sg, nil
}

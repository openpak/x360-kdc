package gateway

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The captured client SYNs (run sg6): the ICV verifies, the plaintext decodes.
func TestReplayClientSYN(t *testing.T) {
	c := newCapture(t)
	s := c.session(t, "sg6")
	c2s, _ := derive(s.material)
	for i, name := range []string{"req-0014.bin", "req-0015.bin", "req-0016.bin"} {
		pkt, _ := c.file(t, "sg6", name)
		sg, err := openTCP(c2s, pkt, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sg.Counter != uint32(i+2) || sg.Flags != flagSYN || sg.Off != 0x60 || sg.Window != 0x4030 ||
			sg.Seq != 0x6f1a097d || sg.Ack != 0 || hex.EncodeToString(sg.Options) != "020404f0" || len(sg.Payload) != 0 {
			t.Fatalf("%s: %+v", name, sg)
		}
		t.Logf("%s: ports %#x -> %#x", name, sg.SrcPort, sg.DstPort)
		if sg.SrcPort != 0xa32e || (sg.DstPort != 25 && sg.DstPort != 80) {
			t.Errorf("%s ports %#x -> %d", name, sg.SrcPort, sg.DstPort)
		}
		// seal with the same material reproduces the datagram byte for byte
		again := sealTCP(c2s, pkt[:4], sg.Counter, sg)
		if !bytes.Equal(again, pkt) {
			t.Errorf("%s: reseal differs\n%x\n%x", name, again, pkt)
		}
	}
}

func TestSealOpenTCP(t *testing.T) {
	c2s, _ := testKeys(t)
	spi := []byte{0, 1, 2, 3}
	for n := 0; n < 20; n++ {
		in := tcpSeg{SrcPort: 0x7098, DstPort: 80, Seq: 7, Ack: 9, Off: 0x50, Flags: flagACK | flagPSH, Window: 0x4030,
			Payload: bytes.Repeat([]byte{0x41}, n)}
		for _, ctr := range []uint32{1, 0x12345} {
			pkt := sealTCP(c2s, spi, ctr, in)
			sg, err := openTCP(c2s, pkt, uint16(ctr>>16))
			if err != nil {
				t.Fatalf("len %d: %v", n, err)
			}
			if sg.Seq != 7 || sg.Ack != 9 || sg.Flags != 0x18 || !bytes.Equal(sg.Payload, in.Payload) || sg.SrcPort != 0x7098 {
				t.Fatalf("len %d: %+v", n, sg)
			}
			pkt[len(pkt)-1] ^= 1
			if _, err := openTCP(c2s, pkt, uint16(ctr>>16)); err == nil {
				t.Fatal("tampered ICV accepted")
			}
		}
	}
}

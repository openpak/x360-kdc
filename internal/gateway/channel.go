package gateway

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// Secure-channel data packets, both directions (firmware senders/receivers
// 8174e518 / 8174dff8, per-packet IV 8174b540):
//
//	SPI(4) | 3DES-CBC(type BE16 | len LE16 (4+body) | body | zero pad to 8) | ctr low16 LE | ICV10
//
// ICV = HMAC-SHA1(hk, ctr_lo16 LE || ctr_hi16 LE || SPI as on the wire || ciphertext)[:10].

// dirKeys is one direction's key set.
type dirKeys struct {
	hk   []byte // 16-byte HMAC key
	k    []byte // 24-byte 3DES key
	seed []byte // 8-byte IV seed
}

// derive splits the 100-byte key material. Client-to-server uses
// [0:16]/[16:40]/[80:88]; server-to-client (also the handshake tail and the
// 0x5887 record) uses [40:56]/[56:80]/[88:96].
func derive(material []byte) (c2s, s2c dirKeys) {
	m := material
	c2s = dirKeys{hk: m[0:16], k: m[16:40], seed: m[80:88]}
	s2c = dirKeys{hk: m[40:56], k: m[56:80], seed: m[88:96]}
	return
}

// ivFor is the firmware's per-packet IV: the seed as two LE u32 x and y,
// each multiplied by the 32-bit counter as 64-bit; IV = LE32(hi(y)^lo(x)) ||
// LE32(lo(y)^hi(x)).
func ivFor(seed []byte, counter uint32) []byte {
	x := uint64(binary.LittleEndian.Uint32(seed[0:4])) * uint64(counter)
	y := uint64(binary.LittleEndian.Uint32(seed[4:8])) * uint64(counter)
	lo := func(v uint64) uint32 { return uint32(v) }
	hi := func(v uint64) uint32 { return uint32(v >> 32) }
	iv := binary.LittleEndian.AppendUint32(nil, hi(y)^lo(x))
	return binary.LittleEndian.AppendUint32(iv, lo(y)^hi(x))
}

func dataMAC(hk, spi []byte, counter uint32, ct []byte) []byte {
	h := hmac.New(sha1.New, hk)
	h.Write(binary.LittleEndian.AppendUint16(nil, uint16(counter)))
	h.Write(binary.LittleEndian.AppendUint16(nil, uint16(counter>>16)))
	h.Write(spi)
	h.Write(ct)
	return h.Sum(nil)[:10]
}

func cbc(key, iv, in []byte, encrypt bool) ([]byte, error) {
	blk, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(in)%des.BlockSize != 0 {
		return nil, errors.New("3DES-CBC input is not a multiple of 8")
	}
	out := make([]byte, len(in))
	if encrypt {
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, in)
	} else {
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, in)
	}
	return out, nil
}

// seal builds one data datagram.
func seal(d dirKeys, spi []byte, counter uint32, mtype uint16, body []byte) []byte {
	pt := binary.BigEndian.AppendUint16(nil, mtype)
	pt = binary.LittleEndian.AppendUint16(pt, uint16(len(body)+4))
	pt = append(pt, body...)
	pt = append(pt, make([]byte, -len(pt)&7)...)
	ct, err := cbc(d.k, ivFor(d.seed, counter), pt, true)
	if err != nil {
		panic(err) // key is always 24 bytes, input padded
	}
	pkt := append(append([]byte{}, spi...), ct...)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(counter))
	return append(pkt, dataMAC(d.hk, spi, counter, ct)...)
}

// parse splits a data datagram into SPI, ciphertext, counter low 16 and ICV.
func parse(pkt []byte) (spi, ct []byte, ctr uint16, icv []byte, err error) {
	if len(pkt) < 4+12 {
		return nil, nil, 0, nil, fmt.Errorf("data packet too short (%d bytes)", len(pkt))
	}
	n := len(pkt)
	return pkt[:4], pkt[4 : n-12], binary.LittleEndian.Uint16(pkt[n-12:]), pkt[n-10:], nil
}

// message is one decrypted secure-channel message.
type message struct {
	Type    uint16
	Counter uint32
	Body    []byte
}

// open verifies the ICV (counter taken from the wire, high half 0) and
// decrypts. Order mirrors the oracle: ICV first, then the cipher.
func open(d dirKeys, pkt []byte) (spi []byte, m message, err error) {
	spi, ct, ctr, icv, err := parse(pkt)
	if err != nil {
		return nil, m, err
	}
	if !hmac.Equal(icv, dataMAC(d.hk, spi, uint32(ctr), ct)) {
		return spi, m, fmt.Errorf("data ICV mismatch (packet %d bytes, ciphertext %d)", len(pkt), len(ct))
	}
	if len(ct) == 0 || len(ct)%des.BlockSize != 0 {
		return spi, m, errors.New("data ciphertext is not a positive multiple of 8")
	}
	pt, err := cbc(d.k, ivFor(d.seed, uint32(ctr)), ct, false)
	if err != nil {
		return spi, m, err
	}
	size := int(binary.LittleEndian.Uint16(pt[2:4]))
	if size < 4 || size > len(pt) {
		return spi, m, errors.New("data message size")
	}
	return spi, message{Type: binary.BigEndian.Uint16(pt), Counter: uint32(ctr), Body: pt[4:size]}, nil
}

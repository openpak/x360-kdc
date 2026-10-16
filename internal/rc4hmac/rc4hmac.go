// Package rc4hmac is Kerberos etype 23 (RC4-HMAC) as the Xbox 360 firmware
// uses it, plus the firmware's key derivation D(K,N).
//
// Packet = checksum[16] || RC4(confounder[8] || plaintext). With
// K1 = HMAC-MD5(key, LE32(usage)): checksum = HMAC-MD5(K1, confounder ||
// plaintext), RC4 key = HMAC-MD5(K1, checksum). The receiver (firmware
// 81947358) validates all 16 checksum bytes, and so does this package.
package rc4hmac

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
)

// KeyLen is the etype 23 key size.
const KeyLen = 16

// Usages seen on the wire. The firmware chooses them; the server mirrors them.
const (
	UsageTimestamp     = 1    // PA-ENC-TIMESTAMP
	UsageTicket        = 2    // the server's own ticket enc-part (server choice)
	UsageAuthenticator = 7    // AP-REQ authenticator in a TGS-REQ
	UsageReply         = 8    // AS-REP / TGS-REP enc-part
	UsageD6            = 1201 // padata 0xD6 request record
	UsageD7            = 1202 // padata 0xD7 service record
	UsageCB            = 1203 // padata 0xCB account record
)

// ErrChecksum is returned when the 16-byte checksum does not verify.
var ErrChecksum = errors.New("rc4hmac: checksum mismatch")

func hm(key, b []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(b)
	return h.Sum(nil)
}

func usageKey(key []byte, usage uint32) []byte {
	return hm(key, binary.LittleEndian.AppendUint32(nil, usage))
}

func stream(key, b []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err) // key is always 16 bytes here
	}
	out := make([]byte, len(b))
	c.XORKeyStream(out, b)
	return out
}

// Encrypt seals plaintext with a fresh random confounder.
func Encrypt(key []byte, usage uint32, plaintext []byte) []byte {
	conf := make([]byte, 8)
	if _, err := rand.Read(conf); err != nil {
		panic(err)
	}
	return encryptWith(key, usage, conf, plaintext)
}

func encryptWith(key []byte, usage uint32, conf, plaintext []byte) []byte {
	k1 := usageKey(key, usage)
	p := append(append([]byte{}, conf...), plaintext...)
	sum := hm(k1, p)
	return append(sum, stream(hm(k1, sum), p)...)
}

// Decrypt verifies the checksum and returns the plaintext without confounder.
func Decrypt(key []byte, usage uint32, packet []byte) ([]byte, error) {
	if len(packet) < 16+8 {
		return nil, errors.New("rc4hmac: packet too short")
	}
	k1 := usageKey(key, usage)
	sum := packet[:16]
	p := stream(hm(k1, sum), packet[16:])
	if !hmac.Equal(hm(k1, p), sum) {
		return nil, ErrChecksum
	}
	return p[8:], nil
}

// Derive is the firmware's D(K,N) (81946 8B0):
// HMAC-MD5(HMAC-MD5(K, "signaturekey\0"), MD5(02 04 00 00 || LE32(N))).
func Derive(key []byte, n uint32) []byte {
	inner := hm(key, []byte("signaturekey\x00"))
	m := md5.Sum(binary.LittleEndian.AppendUint32([]byte{0x02, 0x04, 0x00, 0x00}, n))
	return hm(inner, m[:])
}

// NewKey returns 16 random bytes.
func NewKey() []byte {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

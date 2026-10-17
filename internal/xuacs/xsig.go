package xuacs

// Live service 12, /xsig/ValidateCertificate.ashx (XRL 0xC0B). XAM's TLS
// provider checks only the name and dates of a Windows Live ID server's
// certificate itself, then pauses the handshake and asks Live whether the leaf
// is trusted (XNet SSL socket 0x81773940 -> FUN_81828FB0). A non-zero answer
// closes the socket without an alert (80151103 at the user logon).
//
// Request: u16 LE length | leaf DER. Reply (12 bytes): u32 LE HRESULT (0 =
// trusted) | u64 LE FILETIME until which XAM may cache the verdict for this
// leaf (keyed by its SHA-1).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	PathValidateCert = "/xsig/ValidateCertificate.ashx"

	hrCertUntrusted = 0x80090325 // SEC_E_UNTRUSTED_ROOT
	certCacheTTL    = 24 * time.Hour
)

// fileTime converts to a Windows FILETIME (100 ns since 1601).
func fileTime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func (h *Handler) validateCert(body []byte) []byte {
	r := &reader{b: body}
	der := r.lv()
	hr := uint32(hrCertUntrusted)
	exp := uint64(0)
	trusted := !r.bad && len(der) > 0 && h.TrustLeaf != nil && h.TrustLeaf(der)
	if trusted {
		hr, exp = 0, fileTime(h.now().Add(certCacheTTL))
	}
	sum := sha256.Sum256(der)
	h.log().Info("validate certificate", "body_len", len(body), "der_len", len(der), "sha256", hex.EncodeToString(sum[:]), "trusted", trusted)
	out := binary.LittleEndian.AppendUint32(nil, hr)
	return binary.LittleEndian.AppendUint64(out, exp)
}

// Package der is the small ASN.1 DER subset the Xbox 360 Kerberos exchange
// uses: definite-length TLVs, SEQUENCE, context tags, INTEGER, OCTET STRING,
// GeneralString, GeneralizedTime, BIT STRING and application tags.
//
// It mirrors the OpenPak oracle's encoder byte for byte, including the
// Kerberos nonce rule: the firmware stores the nonce as a signed 32-bit
// INTEGER, so a nonce with the top bit set is echoed as a 4-byte negative
// INTEGER, never as a 5-byte positive one.
package der

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Universal tags used here.
const (
	TagInteger         = 0x02
	TagBitString       = 0x03
	TagOctetString     = 0x04
	TagSequence        = 0x30
	TagGeneralString   = 0x1b
	TagGeneralizedTime = 0x18
)

// TimeLayout is the Kerberos GeneralizedTime form, always UTC.
const TimeLayout = "20060102150405Z"

var errTruncated = errors.New("der: truncated")

// TLV is one decoded element.
type TLV struct {
	Tag   byte
	Value []byte
	Raw   []byte // the full encoding, tag and length included
}

// Encode wraps value in tag with a DER definite length.
func Encode(tag byte, value []byte) []byte {
	n := len(value)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	default:
		var lb []byte
		for v := n; v > 0; v >>= 8 {
			lb = append([]byte{byte(v)}, lb...)
		}
		hdr = append([]byte{tag, 0x80 | byte(len(lb))}, lb...)
	}
	return append(hdr, value...)
}

// Seq concatenates parts into a SEQUENCE.
func Seq(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return Encode(TagSequence, b)
}

// Ctx wraps value in the constructed context tag [n].
func Ctx(n int, value []byte) []byte { return Encode(0xa0|byte(n), value) }

// App wraps value in the constructed application tag [APPLICATION n].
func App(n int, value []byte) []byte { return Encode(0x60|byte(n), value) }

// Integer encodes a non-negative integer the way the oracle does: minimal
// big-endian bytes with a leading zero when the top bit is set.
func Integer(n uint64) []byte {
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return Encode(TagInteger, b)
}

// Nonce encodes a 32-bit nonce as the canonical signed 32-bit INTEGER the
// firmware's parser expects: the same bit pattern, redundant sign octets
// stripped, never widened to five bytes.
func Nonce(n uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, n)
	for len(b) > 1 {
		sign := byte(0)
		if b[1]&0x80 != 0 {
			sign = 0xff
		}
		if b[0] != sign {
			break
		}
		b = b[1:]
	}
	return Encode(TagInteger, b)
}

// Octet encodes an OCTET STRING.
func Octet(b []byte) []byte { return Encode(TagOctetString, b) }

// String encodes a GeneralString.
func String(s string) []byte { return Encode(TagGeneralString, []byte(s)) }

// Time encodes a GeneralizedTime in UTC with second precision.
func Time(t time.Time) []byte {
	return Encode(TagGeneralizedTime, []byte(t.UTC().Format(TimeLayout)))
}

// ParseTime decodes a GeneralizedTime value.
func ParseTime(v []byte) (time.Time, error) {
	t, err := time.Parse(TimeLayout, string(v))
	if err != nil {
		return time.Time{}, fmt.Errorf("der: generalized time %q: %w", v, err)
	}
	return t, nil
}

// Parse decodes consecutive TLVs covering exactly b.
func Parse(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errTruncated
		}
		tag := b[0]
		n := int(b[1])
		i := 2
		if n&0x80 != 0 {
			z := n & 0x7f
			if z == 0 || z > 4 || len(b) < 2+z {
				return nil, fmt.Errorf("der: bad length form")
			}
			n = 0
			for _, c := range b[2 : 2+z] {
				n = n<<8 | int(c)
			}
			i += z
		}
		if n < 0 || len(b)-i < n {
			return nil, errTruncated
		}
		out = append(out, TLV{Tag: tag, Value: b[i : i+n], Raw: b[:i+n]})
		b = b[i+n:]
	}
	return out, nil
}

// One decodes b as exactly one TLV.
func One(b []byte) (TLV, error) {
	l, err := Parse(b)
	if err != nil {
		return TLV{}, err
	}
	if len(l) != 1 {
		return TLV{}, fmt.Errorf("der: expected one element, got %d", len(l))
	}
	return l[0], nil
}

// Fields decodes b as a list of context-tagged elements [n] and returns the
// single element inside each, keyed by n. A non-context tag or a tag seen
// twice is an error.
func Fields(b []byte) (map[int]TLV, error) {
	l, err := Parse(b)
	if err != nil {
		return nil, err
	}
	out := make(map[int]TLV, len(l))
	for _, e := range l {
		if e.Tag&0xe0 != 0xa0 {
			return nil, fmt.Errorf("der: tag %#x is not a context tag", e.Tag)
		}
		n := int(e.Tag & 0x1f)
		if _, dup := out[n]; dup {
			return nil, fmt.Errorf("der: duplicate field [%d]", n)
		}
		inner, err := One(e.Value)
		if err != nil {
			return nil, fmt.Errorf("der: field [%d]: %w", n, err)
		}
		out[n] = inner
	}
	return out, nil
}

// Uint decodes a non-negative INTEGER value that fits in 64 bits. The nonce
// is read this way too: the oracle treats the request nonce bytes as an
// unsigned big-endian number, whatever the sign bit says.
func Uint(v []byte) (uint64, error) {
	if len(v) == 0 {
		return 0, errors.New("der: empty integer")
	}
	// Allow the canonical leading zero of a positive integer with the top bit set.
	if len(v) > 8 && !(len(v) == 9 && v[0] == 0) {
		return 0, fmt.Errorf("der: integer too long (%d bytes)", len(v))
	}
	var n uint64
	for _, c := range v {
		n = n<<8 | uint64(c)
	}
	return n, nil
}

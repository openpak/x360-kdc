package der

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestEncodeLengths(t *testing.T) {
	if got := Encode(0x04, make([]byte, 127)); got[1] != 127 || len(got) != 129 {
		t.Fatalf("short form: %x", got[:2])
	}
	if got := Encode(0x04, make([]byte, 128)); got[1] != 0x81 || got[2] != 128 {
		t.Fatalf("long form 1: %x", got[:3])
	}
	if got := Encode(0x30, make([]byte, 300)); got[1] != 0x82 || got[2] != 1 || got[3] != 44 {
		t.Fatalf("long form 2: %x", got[:4])
	}
}

func TestNonceSigned32(t *testing.T) {
	// Vectors from the live captures (docs: "Nonce encoding correction") plus edge cases.
	cases := map[uint32]string{
		0xbb9a8148: "0204bb9a8148", // high bit set: four bytes, no sign octet
		0xb3ef5bf0: "0204b3ef5bf0",
		0x06dc7763: "020406dc7763",
		0x7b3d0f67: "02047b3d0f67",
		0x00000005: "020105",
		0x00000080: "02020080",
		0x0000807f: "020300807f",
		0xffffff80: "020180",
		0xffffffff: "0201ff",
		0x00800000: "020400800000",
		0:          "020100",
	}
	for n, want := range cases {
		if got := hex.EncodeToString(Nonce(n)); got != want {
			t.Errorf("Nonce(%#x) = %s, want %s", n, got, want)
		}
	}
}

func TestIntegerUnsigned(t *testing.T) {
	cases := map[uint64]string{0: "020100", 5: "020105", 23: "020117", 0x80: "02020080", 0x1234: "02021234", 1203: "020204b3"}
	for n, want := range cases {
		if got := hex.EncodeToString(Integer(n)); got != want {
			t.Errorf("Integer(%d) = %s, want %s", n, got, want)
		}
		v, err := One(Integer(n))
		if err != nil {
			t.Fatal(err)
		}
		back, err := Uint(v.Value)
		if err != nil || back != n {
			t.Errorf("Uint(Integer(%d)) = %d, %v", n, back, err)
		}
	}
	// A negative-looking nonce is read as its unsigned 32-bit bit pattern, like the oracle.
	if n, _ := Uint([]byte{0xbb, 0x9a, 0x81, 0x48}); n != 0xbb9a8148 {
		t.Fatalf("Uint signed nonce = %#x", n)
	}
}

func TestFieldsAndParse(t *testing.T) {
	msg := App(10, Seq(Ctx(1, Integer(5)), Ctx(2, Integer(10)), Ctx(4, Seq(Ctx(2, String("XBOX.COM"))))))
	outer, err := One(msg)
	if err != nil || outer.Tag != 0x6a {
		t.Fatalf("outer: %v %#x", err, outer.Tag)
	}
	seq, err := One(outer.Value)
	if err != nil || seq.Tag != TagSequence {
		t.Fatal(err)
	}
	f, err := Fields(seq.Value)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Uint(f[1].Value); v != 5 {
		t.Fatalf("pvno %d", v)
	}
	if _, ok := f[3]; ok {
		t.Fatal("phantom field")
	}
	body, err := Fields(f[4].Value)
	if err != nil || string(body[2].Value) != "XBOX.COM" {
		t.Fatalf("body: %v %q", err, body[2].Value)
	}
	if !bytes.Equal(f[4].Raw, Seq(Ctx(2, String("XBOX.COM")))) {
		t.Fatal("Raw must cover the whole element")
	}
	// Duplicates and non-context tags are errors.
	if _, err := Fields(append(Ctx(1, Integer(5)), Ctx(1, Integer(6))...)); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := Fields(Integer(5)); err == nil {
		t.Fatal("universal tag accepted as field")
	}
	// Truncation.
	if _, err := Parse(msg[:len(msg)-1]); err == nil {
		t.Fatal("truncated accepted")
	}
	if _, err := Parse([]byte{0x04, 0x85, 1, 2, 3, 4, 5}); err == nil {
		t.Fatal("5-byte length accepted")
	}
}

func TestTime(t *testing.T) {
	at := time.Date(2037, 7, 20, 23, 34, 33, 0, time.UTC)
	enc := Time(at)
	if string(enc[2:]) != "20370720233433Z" || enc[0] != TagGeneralizedTime {
		t.Fatalf("%x", enc)
	}
	back, err := ParseTime(enc[2:])
	if err != nil || !back.Equal(at) {
		t.Fatal(err, back)
	}
	if _, err := ParseTime([]byte("2037-07-20")); err == nil {
		t.Fatal("bad time accepted")
	}
}

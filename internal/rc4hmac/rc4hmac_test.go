package rc4hmac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := NewKey()
	for _, usage := range []uint32{UsageTimestamp, UsageTicket, UsageAuthenticator, UsageReply, UsageD6, UsageD7, UsageCB} {
		plain := []byte("plaintext for usage")
		pkt := Encrypt(key, usage, plain)
		if len(pkt) != 16+8+len(plain) {
			t.Fatalf("usage %d: packet length %d", usage, len(pkt))
		}
		got, err := Decrypt(key, usage, pkt)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("usage %d: %v %x", usage, err, got)
		}
		if _, err := Decrypt(key, usage+1, pkt); err != ErrChecksum {
			t.Fatalf("usage %d: wrong usage accepted (%v)", usage, err)
		}
		bad := append([]byte{}, pkt...)
		bad[len(bad)-1] ^= 1
		if _, err := Decrypt(key, usage, bad); err != ErrChecksum {
			t.Fatalf("usage %d: tampered ciphertext accepted (%v)", usage, err)
		}
		bad = append([]byte{}, pkt...)
		bad[0] ^= 1
		if _, err := Decrypt(key, usage, bad); err != ErrChecksum {
			t.Fatalf("usage %d: tampered checksum accepted (%v)", usage, err)
		}
	}
	if _, err := Decrypt(key, 1, make([]byte, 23)); err == nil {
		t.Fatal("short packet accepted")
	}
}

// Known-answer test for the packet construction with a fixed confounder, so a
// change in the HMAC/RC4 plumbing is caught without the replay captures.
func TestKnownAnswer(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	conf, _ := hex.DecodeString("1011121314151617")
	pkt := encryptWith(key, UsageReply, conf, []byte("abc"))
	// Independently computed with the oracle's enc() using the same confounder.
	want := "2a436c7d6bab4180457a6168bbc8bd661ddacf5f01b3b1245dde24"
	if got := hex.EncodeToString(pkt); got != want {
		t.Fatalf("known answer: got %s", got)
	}
}

func TestDerive(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	// Independently computed with the oracle's derive().
	cases := map[uint32]string{
		0:          "9463e353c90be6d86fa235c5d9c451de",
		0x7b3d0f67: "88ac664ce0fd46c00c217bf7aea458d4",
	}
	for n, want := range cases {
		got := hex.EncodeToString(Derive(key, n))
		if got != want {
			t.Errorf("Derive(k,%#x) = %s want %s", n, got, want)
		}
	}
	if bytes.Equal(Derive(key, 0), Derive(key, 1)) {
		t.Fatal("derive ignores N")
	}
}

package xuacs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The request-0x2 body the console sent on 2026-10-18 and the reply the
// schema analysis says it accepts.
func TestPresenceAliveResponse(t *testing.T) {
	req, _ := hex.DecodeString("01040000790000000300000025e4cd2d00000000000000000000000000000000dbda39515f00090001000a00020f0000000000000050f22cca1c25e4cd2d0000000000000000000000000000000087724b7c6958a75911cd8eb7732e816c96609395fb733814000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000")
	want, _ := hex.DecodeString("01040000100000000300000025e4cd2d0000000000000000000000000000000000000000000000000000000000000000")
	if got := presenceAliveResponse(req); !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
	if presenceAliveResponse(req[:100]) != nil || presenceAliveResponse(append(req, 1)) != nil {
		t.Fatal("malformed request accepted")
	}
}

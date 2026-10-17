package kdc

import (
	"testing"
	"time"
)

// SGTicketLen is the DER size of the sg/S0 ticket for a console machine
// account (12 decimal digits + "@xbox.com", the only principal the firmware
// presents to the security gateway). The initiation's AP-REQ chunk length
// (0x1bc) that demultiplexes the shared UDP 3074 on the secondary depends on
// it, so a change here changes that rule.
const SGTicketLen = 247

func TestSGTicketSizeForConsoleAccounts(t *testing.T) {
	h := &Handler{TicketKey: make([]byte, 16)}
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	for _, cname := range []string{"478700668470@xbox.com", "000000000001@xbox.com", "999999999999@xbox.com"} {
		if n := len(h.authTicket(AccountRealm, []string{cname}, SGService, make([]byte, 16), now)); n != SGTicketLen {
			t.Fatalf("ticket for %s is %d bytes, want %d", cname, n, SGTicketLen)
		}
	}
}

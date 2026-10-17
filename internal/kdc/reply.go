package kdc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

// Encoders for the replies. Field order and every constant mirror the oracle
// (kdc.py reply(), xetgs.py ticket() and the TGS-REP).

// encPrincipal is PrincipalName { [0] name-type 2, [1] SEQUENCE OF GeneralString }.
func encPrincipal(parts []string) []byte {
	var names []byte
	for _, p := range parts {
		names = append(names, der.String(p)...)
	}
	return der.Seq(der.Ctx(0, der.Integer(nameTypeSI)), der.Ctx(1, der.Encode(der.TagSequence, names)))
}

// encEncryptedData is EncryptedData { [0] etype 23, [2] cipher }, no kvno.
func encEncryptedData(cipher []byte) []byte {
	return der.Seq(der.Ctx(0, der.Integer(etypeRC4)), der.Ctx(2, der.Octet(cipher)))
}

// encPadata is PA-DATA { [1] type, [2] value }.
func encPadata(typ uint64, value []byte) []byte {
	return der.Seq(der.Ctx(1, der.Integer(typ)), der.Ctx(2, der.Octet(value)))
}

// encKey is EncryptionKey { [0] etype 23, [1] keyvalue }.
func encKey(key []byte) []byte {
	return der.Seq(der.Ctx(0, der.Integer(etypeRC4)), der.Ctx(1, der.Octet(key)))
}

// zeroFlags is a KerberosFlags BIT STRING of 32 zero bits (5 bytes incl. the unused-bits octet).
func zeroFlags() []byte { return der.Encode(der.TagBitString, make([]byte, 5)) }

// opaqueTicket is the MACS reply's ticket: a Ticket whose enc-part is 32
// random bytes. The firmware stores it and never decrypts it; the oracle's
// MACS path keeps this shape (only XEAS and TGS issue authenticated tickets).
func opaqueTicket(realm string, service []string) []byte {
	blob := make([]byte, 32)
	if _, err := rand.Read(blob); err != nil {
		panic(err)
	}
	return der.App(1, der.Seq(
		der.Ctx(0, der.Integer(pvno)),
		der.Ctx(1, der.String(realm)),
		der.Ctx(2, encPrincipal(service)),
		der.Ctx(3, encEncryptedData(blob)),
	))
}

// authTicket is a server-issued ticket whose EncTicketPart is RC4-HMAC usage 2
// under the server's ticket key. Ticket contents are opaque to the firmware;
// this format is the server's own and TGS verifies it before replying.
func (h *Handler) authTicket(realm string, cname, service []string, session []byte, now time.Time) []byte {
	return h.ticket(realm, cname, service, session, now, nil)
}

// ticket is authTicket with optional authorization-data ([10], user.go);
// machine-only tickets carry none, so their size is unchanged.
func (h *Handler) ticket(realm string, cname, service []string, session []byte, now time.Time, authData []byte) []byte {
	fields := [][]byte{
		der.Ctx(0, zeroFlags()),
		der.Ctx(1, encKey(session)),
		der.Ctx(2, der.String(realm)),
		der.Ctx(3, encPrincipal(cname)),
		der.Ctx(4, der.Seq(der.Ctx(0, der.Integer(0)), der.Ctx(1, der.Octet(nil)))),
		der.Ctx(5, der.Time(now)),
		der.Ctx(6, der.Time(now)),
		der.Ctx(7, der.Time(now.Add(TicketTL))),
	}
	if authData != nil {
		fields = append(fields, der.Ctx(10, authData))
	}
	plain := der.App(3, der.Seq(fields...))
	return der.App(1, der.Seq(
		der.Ctx(0, der.Integer(pvno)),
		der.Ctx(1, der.String(realm)),
		der.Ctx(2, encPrincipal(service)),
		der.Ctx(3, encEncryptedData(rc4hmac.Encrypt(h.TicketKey, rc4hmac.UsageTicket, plain))),
	))
}

// encKDCRepPart is EncASRepPart / EncTGSRepPart: session key, one last-req
// entry, the signed 32-bit nonce, zero flags, auth/start now, end now+1h,
// server realm and name.
func encKDCRepPart(appTag int, session []byte, nonce uint32, realm string, service []string, now time.Time) []byte {
	return der.App(appTag, der.Seq(
		der.Ctx(0, encKey(session)),
		der.Ctx(1, der.Seq(der.Seq(der.Ctx(0, der.Integer(0)), der.Ctx(1, der.Time(now))))),
		der.Ctx(2, der.Nonce(nonce)),
		der.Ctx(4, zeroFlags()),
		der.Ctx(5, der.Time(now)),
		der.Ctx(6, der.Time(now)),
		der.Ctx(7, der.Time(now.Add(TicketTL))),
		der.Ctx(9, der.String(realm)),
		der.Ctx(10, encPrincipal(service)),
	))
}

// encKDCRep assembles AS-REP (tag 0x6b, type 11) or TGS-REP (0x6d, 13).
// padata may be nil (XEAS has none).
func encKDCRep(appTag int, msgType uint64, padata []byte, realm string, cname []string, ticket, encPart []byte) []byte {
	parts := [][]byte{der.Ctx(0, der.Integer(pvno)), der.Ctx(1, der.Integer(msgType))}
	if padata != nil {
		parts = append(parts, der.Ctx(2, der.Encode(der.TagSequence, padata)))
	}
	parts = append(parts,
		der.Ctx(3, der.String(realm)),
		der.Ctx(4, encPrincipal(cname)),
		der.Ctx(5, ticket),
		der.Ctx(6, encEncryptedData(encPart)),
	)
	return der.App(appTag, der.Seq(parts...))
}

// D7Len is the service record the TGS reply carries in padata 0xD7, and
// D7CipherLen its RC4-HMAC size; the firmware requires both exactly.
const (
	D7Len       = 184
	D7CipherLen = D7Len + 24
	CBCipherLen = AccountLen + 24
)

// Services advertised as available (status 0) in the D7 bitmap: 1 is the
// default the firmware selects, 20 is the security gateway, 25 carries the
// LiveHive request (XRL 0x1300, /liveinfo/GetLiveConfig.ashx) the XLive
// manager issues right after the logon; without it the manager fails with
// 0x80151100 and the logon result becomes 0x80151925; 5 is xuacs, the account service (XRL 0x645..0x1707,
// /xuacs/*.ashx) the Download Profile applet needs; 11 serves the applet's
// CountryInfo download (/xedl/ProfileInfo/<id>/CountryInfo.cib), without it the
// time-zone step fails with 0x800704DB; 12 is xsig, which XAM's TLS provider asks
// to validate a Windows Live ID server certificate mid-handshake. Overridable from the
// environment (X360_KDC_D7_SERVICES) for experiments.
var D7Services = []int{1, 20, 25, 5, 11, 12}

// D7Extended lists the "extended" service entries at D7 offset 0x7C (four
// slots of LE u32 id, LE u16 port, u8 status). Unlike the bitmap services,
// whose port is the service id, these carry an explicit port. Empty by
// default; X360_KDC_D7_EXTENDED="25:80" moves service 25 here.
var D7Extended []ExtendedService

// ExtendedService is one D7 extended entry.
type ExtendedService struct {
	ID   uint32
	Port uint16
}

// d7Record builds the 184-byte record: status 0, SG IPv4 at 0x24 in network
// order, the two-bit service status map at 0x5C (3 = omitted for everything
// but D7Services), the extended entries at 0x7C, and the LE u64 cookie 1 at
// 0xB0. Every other field is zero, as the oracle leaves them.
func d7Record(sg netip.Addr) []byte {
	rec := make([]byte, D7Len)
	ip := sg.As4()
	copy(rec[0x24:0x28], ip[:])
	for i := 0x5c; i < 0x7c; i++ {
		rec[i] = 0xff
	}
	for _, id := range D7Services {
		rec[0x5c+id/4] &^= byte(3 << ((id % 4) * 2))
	}
	for i, e := range D7Extended {
		if i >= 4 {
			break
		}
		off := 0x7c + 7*i
		binary.LittleEndian.PutUint32(rec[off:], e.ID)
		binary.LittleEndian.PutUint16(rec[off+4:], e.Port)
		rec[off+6] = 0
	}
	binary.LittleEndian.PutUint64(rec[0xb0:], 1)
	return rec
}

// ParseD7Services parses "1,20,25"; ParseD7Extended parses "25:80,16:1000".
func ParseD7Services(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 127 {
			return nil, fmt.Errorf("service id %q", f)
		}
		out = append(out, n)
	}
	return out, nil
}

func ParseD7Extended(s string) ([]ExtendedService, error) {
	var out []ExtendedService
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		id, port, ok := strings.Cut(f, ":")
		n, err := strconv.Atoi(id)
		p, err2 := strconv.Atoi(port)
		if !ok || err != nil || err2 != nil || n < 1 || p < 1 || p > 65535 {
			return nil, fmt.Errorf("extended service %q (want id:port)", f)
		}
		out = append(out, ExtendedService{ID: uint32(n), Port: uint16(p)})
	}
	if len(out) > 4 {
		return nil, fmt.Errorf("at most four extended services")
	}
	return out, nil
}

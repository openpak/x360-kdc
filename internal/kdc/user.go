package kdc

// The user AS exchange (XEAS, realm XBOX.COM) of a profile signing in to Live,
// from the 17559 XAM user logon (state machine 0x817366E8, user AS builder
// 0x81948A40 with isMachine = 0):
//
//	cname    "<gamertag>@<domain>", spaces as '_' (domain/realm from 0x63F)
//	padata   0x82 (130) parent TGT: the machine XEAS TGT for the first user,
//	              the previous user's TGT for the next ones
//	         2    encrypted timestamp, usage 1, under K_u
//	         0xCE HMAC-SHA1 under D(K_u, 0) + version/title text
//	         0xDA (218) RC4-HMAC usage 1206 under K_u of u16 BE len || the
//	              base64-decoded Windows Live ID access ticket (XUACS.XBOXLIVE.COM, MBI)
//
//	K_u = HMAC-MD5(HMAC-MD5(XenonKey, "signaturekey\0"), MD5(00 04 00 00 || parent session key))
//
// (0x81946248). The XenonKey is the 16-byte key RecoverAccount (0x63F) issued
// to this profile on this console; x360-xuacs holds it and signs the WLID
// ticket, so both are fetched from its internal API.
//
// Reply: AS-REP without padata, enc-part under K_u usage 8, and a TGT whose
// client is the user principal. The TGT's authorization-data (type adOpenPak)
// carries the console's machine principal and every user authorised along the
// chain; the TGS checks the D6 user ids against it and the security gateway
// reads both.

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

const (
	PaParentTGT = 0x82 // 130
	PaDA        = 0xda // 218: the WLID ticket
	UsageDA     = 1206

	adOpenPak   = 0x4f50 // authorization-data type of our user list
	adMagic     = "OPU1"
	maxDATicket = 800
)

// UserDirectory is what the user AS exchange needs from x360-xuacs.
type UserDirectory interface {
	// UserKey returns the profile issued as gamertag on console (12 digits).
	UserKey(ctx context.Context, console, gamertag string) (account string, online uint64, xenonKey []byte, err error)
	// VerifyTicket checks a WLID access ticket and returns whom it names.
	VerifyTicket(ctx context.Context, ticket []byte) (account string, online uint64, err error)
}

// TicketUser is one signed-in user a ticket carries.
type TicketUser struct {
	XUID    uint64
	Account string
}

// TicketIdentity is who a ticket this server issued speaks for.
type TicketIdentity struct {
	Principal string       // the ticket's client name (machine or user principal)
	Machine   string       // the console's machine principal "<digits>@xbox.com"
	Users     []TicketUser // users authorised along the chain, in order
}

// HasUser reports whether xuid is one of the authorised users.
func (t *TicketIdentity) HasUser(xuid uint64) bool {
	for _, u := range t.Users {
		if u.XUID == xuid {
			return true
		}
	}
	return false
}

// Names are the principals an authenticator under this ticket may carry.
func (t *TicketIdentity) Names() []string {
	if t.Principal == t.Machine {
		return []string{t.Machine}
	}
	return []string{t.Principal, t.Machine}
}

func encAuthData(machine string, users []TicketUser) []byte {
	b := []byte(adMagic)
	b = append(b, byte(len(machine)))
	b = append(b, machine...)
	b = append(b, byte(len(users)))
	for _, u := range users {
		b = binary.BigEndian.AppendUint64(b, u.XUID)
		b = append(b, byte(len(u.Account)))
		b = append(b, u.Account...)
	}
	return der.Seq(der.Seq(der.Ctx(0, der.Integer(adOpenPak)), der.Ctx(1, der.Octet(b))))
}

// ReadTicketIdentity reads the client and the OpenPak authorization-data of
// a decrypted EncTicketPart.
func ReadTicketIdentity(inner map[int]der.TLV) (*TicketIdentity, error) {
	cn, ok := inner[3]
	if !ok {
		return nil, errors.New("ticket principal missing")
	}
	names, err := principal(cn)
	if err != nil || len(names) != 1 {
		return nil, errors.New("ticket principal count")
	}
	id := &TicketIdentity{Principal: names[0], Machine: names[0]}
	ad, ok := inner[10]
	if !ok {
		return id, nil
	}
	if ad.Tag != der.TagSequence {
		return nil, errors.New("authorization-data")
	}
	items, err := der.Parse(ad.Value)
	if err != nil {
		return nil, errors.New("authorization-data")
	}
	for _, it := range items {
		f, err := der.Fields(it.Value)
		if err != nil {
			return nil, errors.New("authorization-data entry")
		}
		if t, err := uintField(f, 0); err != nil || t != adOpenPak {
			continue
		}
		v, ok := f[1]
		if !ok {
			return nil, errors.New("authorization-data value")
		}
		b := v.Value
		if len(b) < 6 || string(b[:4]) != adMagic {
			return nil, errors.New("authorization-data magic")
		}
		n := int(b[4])
		if len(b) < 6+n {
			return nil, errors.New("authorization-data length")
		}
		id.Machine = string(b[5 : 5+n])
		b = b[5+n:]
		cnt := int(b[0])
		b = b[1:]
		for i := 0; i < cnt; i++ {
			if len(b) < 9 || len(b) < 9+int(b[8]) {
				return nil, errors.New("authorization-data user")
			}
			l := int(b[8])
			id.Users = append(id.Users, TicketUser{XUID: binary.BigEndian.Uint64(b), Account: string(b[9 : 9+l])})
			b = b[9+l:]
		}
	}
	return id, nil
}

// openTicket decrypts a Ticket this server issued and checks realm and
// validity; it returns the EncTicketPart fields and the session key.
func (h *Handler) openTicket(raw []byte, now time.Time) (map[int]der.TLV, []byte, error) {
	tf, err := appSeqFields(raw, tagTicket)
	if err != nil {
		return nil, nil, fmt.Errorf("ticket: %w", err)
	}
	if realm, ok := tf[1]; !ok || string(realm.Value) != AccountRealm {
		return nil, nil, errors.New("ticket realm")
	}
	enc, ok := tf[3]
	if !ok {
		return nil, nil, errors.New("ticket enc-part missing")
	}
	cipher, err := encryptedData(enc.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("ticket enc-part: %w", err)
	}
	plain, err := rc4hmac.Decrypt(h.TicketKey, rc4hmac.UsageTicket, cipher)
	if err != nil {
		return nil, nil, errors.New("ticket not issued by this server")
	}
	inner, err := appSeqFields(plain, tagEncTkt)
	if err != nil {
		return nil, nil, fmt.Errorf("EncTicketPart: %w", err)
	}
	start, err1 := timeField(inner, 6)
	end, err2 := timeField(inner, 7)
	if err1 != nil || err2 != nil || now.Before(start) || now.After(end) {
		return nil, nil, errors.New("ticket validity")
	}
	kf, ok := inner[1]
	if !ok {
		return nil, nil, errors.New("ticket session key missing")
	}
	session, err := keyValue(kf)
	if err != nil {
		return nil, nil, fmt.Errorf("ticket session key: %w", err)
	}
	return inner, session, nil
}

// findTicket returns the first [APPLICATION 1] element inside b (padata 0x82
// wraps the parent ticket in the firmware's own {u32 0, Ticket} record).
func findTicket(b []byte) []byte {
	items, err := der.Parse(b)
	if err != nil {
		return nil
	}
	for _, it := range items {
		if it.Tag == tagTicket {
			return it.Raw
		}
		if it.Tag&0x20 != 0 { // constructed: look inside
			if t := findTicket(it.Value); t != nil {
				return t
			}
		}
	}
	return nil
}

// UserKey derives K_u from the XenonKey and the parent TGT session key.
func UserKey(xenonKey, parentSession []byte) []byte {
	m := hmac.New(md5.New, xenonKey)
	m.Write([]byte("signaturekey\x00"))
	ksign := m.Sum(nil)
	d := md5.Sum(append([]byte{0x00, 0x04, 0x00, 0x00}, parentSession...))
	m = hmac.New(md5.New, ksign)
	m.Write(d[:])
	return m.Sum(nil)
}

// userAS answers a user AS-REQ (padata 0xDA present).
func (h *Handler) userAS(r *kdcReq, cname []string) ([]byte, []any, error) {
	if h.Directory == nil {
		return nil, nil, errors.New("user AS: no user directory configured (X360_KDC_XUACS_URL)")
	}
	if len(cname) != 1 {
		return nil, nil, errors.New("user AS: principal count")
	}
	gamertag, domain, ok := strings.Cut(cname[0], "@")
	if !ok || gamertag == "" || !strings.EqualFold(domain, AccountDomain) {
		return nil, nil, fmt.Errorf("user AS: principal %q", cname[0])
	}
	for _, t := range []int{PaParentTGT, PaEncTS, PaDA} {
		if _, ok := r.padata[t]; !ok {
			return nil, nil, fmt.Errorf("user AS: padata %d missing", t)
		}
	}
	now := h.now()
	raw := findTicket(r.padata[PaParentTGT])
	if raw == nil {
		return nil, nil, errors.New("user AS: no ticket in padata 0x82")
	}
	inner, parentSession, err := h.openTicket(raw, now)
	if err != nil {
		return nil, nil, fmt.Errorf("user AS: parent %w", err)
	}
	parent, err := ReadTicketIdentity(inner)
	if err != nil {
		return nil, nil, fmt.Errorf("user AS: parent %w", err)
	}
	acct := h.Accounts.Get(parent.Machine)
	if acct == nil || !acct.ConsoleSignatureVerified {
		return nil, nil, errors.New("user AS: parent ticket is not a verified console")
	}
	cert, err := acct.Cert()
	if err != nil {
		return nil, nil, fmt.Errorf("user AS: %w", err)
	}
	if err := VerifyCA(h.CA, cert); err != nil {
		return nil, nil, fmt.Errorf("user AS: stored certificate: %w", err)
	}
	console := ConsoleDigits(cert)
	attrs := []any{"user", cname[0], "console", console, "parent", parent.Principal}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	account, online, xenon, err := h.Directory.UserKey(ctx, console, gamertag)
	if err != nil {
		return nil, attrs, fmt.Errorf("user AS: profile lookup: %w", err)
	}
	attrs = append(attrs, "account", account, "online", fmt.Sprintf("%016x", online))

	// K_u per 0x81946248; the XenonKey itself is what the firmware uses when a
	// logon context has no parent, kept as a logged fallback.
	var key []byte
	var ts time.Time
	for _, k := range [][]byte{UserKey(xenon, parentSession), xenon} {
		if t, err := decryptTimestamp(k, r.padata[PaEncTS]); err == nil {
			key, ts = k, t
			break
		}
	}
	if key == nil {
		return nil, attrs, errors.New("user AS: timestamp does not decrypt under K_u (wrong XenonKey or derivation)")
	}
	attrs = append(attrs, "key", map[bool]string{true: "derived", false: "xenon"}[!hmac.Equal(key, xenon)])
	if d := now.Sub(ts); d >= Freshness || d <= -Freshness {
		return nil, attrs, errors.New("user AS: timestamp outside 5 minutes")
	}
	title, ceErr := verifyCE(rc4hmac.Derive(key, 0), r.padata[PaCE])
	attrs = append(attrs, "title", title, "ce_ok", ceErr == nil)

	da, err := encryptedData(r.padata[PaDA])
	if err != nil {
		return nil, attrs, fmt.Errorf("user AS: DA: %w", err)
	}
	plain, err := rc4hmac.Decrypt(key, UsageDA, da)
	if err != nil {
		return nil, attrs, errors.New("user AS: DA checksum")
	}
	if len(plain) < 2 || int(binary.BigEndian.Uint16(plain)) > len(plain)-2 || binary.BigEndian.Uint16(plain) > maxDATicket {
		return nil, attrs, errors.New("user AS: DA length")
	}
	ticket := plain[2 : 2+binary.BigEndian.Uint16(plain)]
	tAcct, tOnline, err := h.Directory.VerifyTicket(ctx, ticket)
	if err != nil {
		return nil, attrs, fmt.Errorf("user AS: WLID ticket: %w", err)
	}
	if tAcct != account || tOnline != online {
		return nil, attrs, fmt.Errorf("user AS: WLID ticket names %s/%016x, profile is %s/%016x", tAcct, tOnline, account, online)
	}

	users := append([]TicketUser{}, parent.Users...)
	if !parent.HasUser(online) {
		users = append(users, TicketUser{XUID: online, Account: account})
	}
	session := rc4hmac.NewKey()
	service := []string{Krbtgt, r.realm}
	tgt := h.ticket(r.realm, cname, service, session, now, encAuthData(parent.Machine, users))
	part := encKDCRepPart(25, session, r.nonce, r.realm, service, now)
	rep := encKDCRep(11, msgASRep, nil, r.realm, cname, tgt, rc4hmac.Encrypt(key, rc4hmac.UsageReply, part))
	attrs = append(attrs, "users", len(users), "client_time", ts.UTC().Format(time.RFC3339))
	return rep, attrs, nil
}

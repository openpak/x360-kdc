package kdc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"openpak/x360-kdc/internal/der"
	"openpak/x360-kdc/internal/rc4hmac"
)

type fakeDir struct {
	key    []byte
	online uint64
	ticket []byte
}

func (f *fakeDir) Profiles(_ context.Context, console, tag string) ([]Profile, error) {
	if console != "478700668470" || (tag != "Ann_Smith" && tag != "") {
		return nil, errors.New("no profile")
	}
	other := Profile{Account: "A-bob", Online: 0x0009000000000002, XenonKey: bytes.Repeat([]byte{9}, 16)}
	return []Profile{other, {Account: "A-ann", Online: f.online, XenonKey: f.key}}, nil
}

func (f *fakeDir) VerifyTicket(_ context.Context, t []byte) (string, uint64, error) {
	if !bytes.Equal(t, f.ticket) {
		return "", 0, errors.New("bad ticket")
	}
	return "A-ann", f.online, nil
}

func userASReq(name string, parentTGT, ku, ticket []byte, nonce uint32, at time.Time) []byte {
	pa82 := der.Seq(der.Ctx(0, der.Integer(0)), der.Ctx(1, parentTGT))
	da := binary.BigEndian.AppendUint16(nil, uint16(len(ticket)))
	da = append(da, ticket...)
	pa := []paItem{
		{PaParentTGT, pa82},
		{PaEncTS, encTimestamp(ku, at)},
		{PaCE, ceBlock(rc4hmac.Derive(ku, 0), ceText)},
		{PaDA, encEncryptedData(rc4hmac.Encrypt(ku, UsageDA, da))},
	}
	return kdcReqMsg(10, msgASReq, pa, reqBody(clientPrincipal(10, name), AccountRealm, []string{Krbtgt, AccountRealm}, nonce))
}

func TestUserLogon(t *testing.T) {
	h, ca := testHandler(t, t0)
	c := newConsole(t, ca, [5]byte{0x6f, 0x74, 0xc8, 0x86, 0x36})
	req, secret := c.macsReq(t, &h.XMACS.PublicKey, 1, t0)
	rep, _ := handle(t, h, req)
	cb := decodeCB(t, decodeRep(t, rep, tagASRep, msgASRep, secret, 1, tagEncAS), secret, 1)
	machine := "478700668470@xbox.com"
	xrep, _ := handle(t, h, xeasReq(machine, cb[68:84], 2, t0))
	xas := decodeRep(t, xrep, tagASRep, msgASRep, cb[68:84], 2, tagEncAS)

	dir := &fakeDir{key: rc4hmac.NewKey(), online: 0x0009000012345678, ticket: []byte("OPW1-ticket")}
	ku := UserKey(dir.key, xas.session)
	user := "Ann_Smith@xbox.com"

	// No directory: refused.
	reject(t, h, userASReq(user, xas.ticket, ku, dir.ticket, 3, t0), "no user directory")
	h.Directory = dir
	// Wrong key derivation, wrong ticket.
	reject(t, h, userASReq(user, xas.ticket, rc4hmac.NewKey(), dir.ticket, 4, t0), "timestamp does not decrypt")
	reject(t, h, userASReq(user, xas.ticket, ku, []byte("forged"), 5, t0), "WLID ticket")

	// Empty gamertag ("@xbox.com", as the 17559 logon sends it): found by key.
	if _, res := handle(t, h, userASReq("@xbox.com", xas.ticket, ku, dir.ticket, 7, t0)); res.Kind != KindUserAS {
		t.Fatal(res.Kind)
	}
	urep, res := handle(t, h, userASReq(user, xas.ticket, ku, dir.ticket, 6, t0))
	if res.Kind != KindUserAS {
		t.Fatal(res.Kind)
	}
	uas := decodeRep(t, urep, tagASRep, msgASRep, ku, 6, tagEncAS)
	if n, _ := principal(uas.fields[4]); len(n) != 1 || n[0] != user {
		t.Fatalf("AS-REP cname %v", n)
	}
	inner, _, err := h.openTicket(uas.ticket, t0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ReadTicketIdentity(inner)
	if err != nil || id.Machine != machine || id.Principal != user || !id.HasUser(dir.online) {
		t.Fatalf("identity %+v %v", id, err)
	}

	// TGS with the user id: accepted, under either authenticator name.
	withUser := func(d6 []byte, _ *[][]byte) { binary.LittleEndian.PutUint64(d6[d6UsersOff:], dir.online) }
	for i, name := range []string{user, machine} {
		trep, tres := handle(t, h, tgsReq(name, uas.ticket, uas.session, uint32(10+i), t0, withUser))
		if tres.Kind != KindTGS {
			t.Fatal(tres.Kind)
		}
		tr := decodeRep(t, trep, tagTGSRep, msgTGSRep, uas.session, uint32(10+i), tagEncTGS)
		d7 := decodeD7(t, tr, rc4hmac.Derive(uas.session, uint32(10+i)))
		for j := 0; j < 4; j++ {
			if binary.LittleEndian.Uint32(d7[4+4*j:]) != 0 {
				t.Fatalf("user %d result word not zero", j)
			}
		}
		sin, _, err := h.openTicket(tr.ticket, t0)
		if err != nil {
			t.Fatal(err)
		}
		if sid, _ := ReadTicketIdentity(sin); !sid.HasUser(dir.online) || sid.Machine != machine {
			t.Fatalf("sg ticket identity %+v", sid)
		}
	}
	// A user the chain did not authorise.
	other := func(d6 []byte, _ *[][]byte) { binary.LittleEndian.PutUint64(d6[d6UsersOff+8:], 0x0009000099999999) }
	reject(t, h, tgsReq(user, uas.ticket, uas.session, 20, t0, other), "not authorised")
	// Machine TGT with the user id: refused.
	reject(t, h, tgsReq(machine, xas.ticket, xas.session, 21, t0, withUser), "not authorised")
}

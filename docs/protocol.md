# Protocol: x360-kdc

OpenPak's Xbox 360 Kerberos endpoint: the three exchanges the 360 firmware (17559) runs over **UDP port 88**
when it signs in to Xbox Live, served by one process on one socket:

| Stage | Hostname the firmware resolves | Realm | What it is |
|---|---|---|---|
| MACS | `xemacs.xboxlive.com` | `MACS.XBOX.COM` | console authentication: RSA/CA-signed console certificate, issues the machine account (padata 0xDB in, 0xCB out) |
| XEAS | `xeas.xboxlive.com` | `XBOX.COM` | machine-account AS exchange with the issued key, returns a TGT (padata 0xD8) |
| XETGS | `xetgs.xboxlive.com` | `XBOX.COM` | TGS-REQ for the security gateway `sg/S0`, returns the service record (padata 0xD6 in, 0xD7 out) |

## Protocol

Everything below is derived from the firmware's own code by OpenPak (clean room; see
[clean-room policy](https://docs.openpak.org/contributors/clean-room/)). Source of truth with offsets and firmware
addresses: internal research notes, the three dated
sections "MACS console authentication and AS-REP", "XEAS account authentication accepted" and "XETGS sg/S0
reply". This README only summarises what the server enforces.

Common to all three: Kerberos v5 DER, etype 23 (RC4-HMAC: `checksum[16] || RC4(confounder[8] || plaintext)`,
`K1 = HMAC-MD5(key, LE32(usage))`, all 16 checksum bytes verified) and the firmware's key derivation
`D(K,N) = HMAC-MD5(HMAC-MD5(K, "signaturekey\0"), MD5(02 04 00 00 || LE32(N)))`. The request nonce is a
**signed 32-bit INTEGER**: a nonce with the top bit set is echoed as the same four bytes, never widened to five.
Replies reuse the request's realm and principal; every ticket, start/end time (+1 h) and session key is the
server's own.

**MACS** (AS-REQ, cname `XE.<12 console digits>`): padata 0xDB is 828 bytes: little-endian RSA-2048 OAEP
(SHA1/MGF1-SHA1) ciphertext of the 16-byte secret K, 8-byte timestamp, 12-byte serial, 128-byte console
PKCS#1 v1.5 SHA1 signature over `SHA1(timestamp || serial || SHA1(K))`, and the 424-byte console certificate
whose CA signature (RSA-2048 PSS SHA1/MGF1-SHA1, salt 10, over bytes 0..0xA8) must verify against
`X360_KDC_CONSOLE_CA`. The console ID in the certificate must match the cname. Padata 0xCE is
`HMAC-SHA1(D(K,0), text)` over the NUL-terminated version/title text; padata 2 is the encrypted timestamp
(usage 1). Reply: AS-REP with an opaque ticket, padata 0xCB = EncryptedData of the 84-byte account record under
`D(K, nonce)` usage 1203 (cipher exactly 108 bytes), enc-part under K usage 8. The account (id
`0x0009 << 48 | console ID`, name = console digits, domain `xbox.com`, realm `XBOX.COM`, fresh 16-byte key)
is persisted with its certificate and a provenance flag; the same certificate reuses the key, a new certificate
for the same console replaces it.

**XEAS** (AS-REQ, cname `<digits>@xbox.com`): the account must exist with verified provenance and its stored
certificate must still verify against the CA. Padata set exactly {0xD8 (20 bytes, logged only), 0xCE under
`D(accountKey,0)`, 2 (usage 1, within 5 minutes)}. Reply: AS-REP without padata, an authenticated TGT
(EncTicketPart under the server's ticket key, usage 2), enc-part under the account key usage 8.

**XETGS** (TGS-REQ, sname `sg/S0`, no body cname): padata set exactly {1 AP-REQ, 0xCE, 0xD6}. The AP-REQ
ticket must be a TGT this server issued (decrypts under the ticket key, realm `XBOX.COM`, within its
validity, principal is a stored verified account). The authenticator (usage 7 under the TGT session key) must
name the same principal, be within 5 minutes, carry no subkey, and hold an MD5 (type 7) of the exact DER
request body. 0xCE and 0xD6 (usage 1201, plaintext exactly 126 bytes, version 6) use `D(session, nonce)`;
the four user ids in D6 must be zero (user sign-in is not implemented and is refused, never silently granted).
Reply: TGS-REP with padata 0xD7 = EncryptedData of the 184-byte service record under `D(session, nonce)`
usage 1202 (cipher exactly 208 bytes): status 0, the SG IPv4 at 0x24, services **1, 20 and 25** available in the
two-bit status map at 0x5C (all others omitted), cookie 1 at 0xB0; plus a fresh `sg/S0` ticket and the enc-part
under the TGT session key usage 8.

Any check that fails means **no reply**; the firmware times out and retries, as it did against the oracle.
There is no unsigned, unknown-identity or source-address fallback. Rejections are logged at info level with
the reason, realm, principal, nonce and padata sizes, never with key material. KRB-ERROR replies are not sent
(the oracle sent none; the firmware's error handling is documented but was never exercised live).

## LiveHive (`x360-liveinfo`)

Third binary in the image (`/usr/local/bin/x360-liveinfo`, own entrypoint). After the Live logon xam.xex issues
XRL request 0x1300 = HTTP POST `/liveinfo/GetLiveConfig.ashx` (`Content-Type: xon/19`, 8-byte body) to Live
service 25, and 0x1301 = `/liveinfo/getnetworkauthorizationlist.ashx` (empty body), carried through the security
gateway. The answers are XRL binary bodies, little-endian: GetLiveConfig = `u32 total | u16 chunks (1..10) |
{u16 len, bytes}...` whose chunks join into ASCII `key=value;key=value;...` (a literal `^` escapes the next
character, total below 0x7531, **no NUL on the wire**); the network authorization list = `u16 count` (empty:
`00 00`, acceptance unverified). The example hive is
`22000000 0100 2200 "LiveHivePollFrequencyInMinutes=120"` (42 bytes). The server emits
`LiveHivePollFrequencyInMinutes` (clamped 30..240 by XAM, default 120) and `SMRevision` only when configured:
a present `SMRevision` must equal the console's local revision (`126d69eb6cf3737c` for the public 17559 update)
or XAM asks for a system update, so OpenPak omits it. `^`, `;` and `=` in values are escaped with `^`.

## Account service (`x360-xuacs`)

Fourth binary in the image (`/usr/local/bin/x360-xuacs`). Live service 5 is `xuacs`; D7 now advertises services
1, 20, 25 and 5 (port = id, so the gateway sees destination port 5 and routes it with `X360_GATEWAY_SERVICE_URLS`,
or Traefik `PathPrefix(/xuacs)` on port 80 does). It answers what the Guide.AccountRecovery applet ("Download
Profile") sends: HTTP POST, `Content-Type: xon/5`, `X-Schema-Ver: 6.5`, little-endian bodies, strings
`u16 len | bytes`. Spec: `private notes` sections 4-6 and
`xon-hive-format.md`. Code: `internal/xuacs`, `cmd/x360-xuacs`.

**Envelope decision.** The XRL engine adds no envelope: the wire body is exactly the fields of the response
schema. GetLiveConfig's `u32 total | u16 chunks | {u16 len, bytes}` is that one schema's own fields, so xuacs
replies are the raw fields of the table below, with nothing around them. Not switchable; if a capture shows a
wrapper, only `respond` in `xuacs.go` changes.

| XRL | path | request | reply |
|---|---|---|---|
| 0x645 | `PassportMemberNameExists.ashx` | `u16 L \| email \| NUL` | `01` |
| 0x64A (0x606) | `XePassportGetEncryptedProxyParameters.ashx` | `u32` | `u16 32 \| proxy blob \| u32 exponent \| u16 256 \| modulus (BE) \| 20 bytes` |
| 0x608 | `XePassportLogin.ashx` | email, 256 B OAEP-wrapped 3DES key, 48 B password blob, proxy blob, `u32` | 28-byte token |
| 0x60E | `XeGetLinkedGamertag.ashx` | token | `u64` online XUID, `u16 L \| gamertag \| NUL` |
| 0x624 | `XeGetUserType.ashx` | `u64`, `u16 L \| gamertag` | `02` |
| 0x1707 | `EnumFamilyMembers.ashx` | `u64`, `u16 N`, N tokens | `00 00` |
| 0x63F | `RecoverAccount.ashx` | 45 B: machine id, token, online XUID, isDependent | online XUID, offline XUID, 16 B XenonKey, gamertag, `xbox.com`, `XBOX.COM` |
| 0x649 | same path | variable (TFA receipt / RPS token) | refused with 501 and a logged error |
| 0x627 | `XeGetAccountInfoFromPassport.ashx` | token, `u64` machine id, `u32` title id | gamertag, empty strings, DOB 2000-01-01, country 103 |

**CountryInfo (Live service 11).** After 0x627 the applet's time-zone step downloads
`/xedl/ProfileInfo/<CountryId>/CountryInfo.cib` from service 11 (GET, no body). D7 must list 11: without it the
console's service lookup fails before any packet (0x80151100, shown as 800704DB with the "problem with the
credentials" dialog). x360-xuacs serves the file for every country id (Traefik `PathPrefix(/xedl)`): big-endian,
UTF-16BE NUL-terminated strings, US settings, default time zone `PACIFIC`, one English locale, empty lists. Layout
in `internal/xuacs/countryinfo.go`.

**0x608.** The 24-byte 3DES key is RSA-OAEP (SHA-1, empty label) wrapped to the key 0x64A advertises. The password
blob (3DES-CBC, IV 0, PKCS padding) is the password padded to 20 bytes with the fill byte `20-len`, then the 20-byte
UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`; the skew must be at most 5 minutes (`X360_XUACS_MAX_SKEW`). The proxy blob
must be one issued by 0x64A in the last 15 minutes (reusable inside that window). The password is checked with
`Identity.VerifyPassword` (two-factor accounts fail closed), then a 28-byte random token, valid 24 hours, is bound
to the account. Wrong credentials answer HTTP 401, skew or unknown proxy blob 403, malformed bodies 400, core
errors 503.

**Identity.** Online XUID = `0x0009` high word plus: the subject of the account's active `x360` link when it has
one, else 40 bits derived from SHA-256 of the account id (stored, collision-checked). Gamertag = the link's public
code, else the letters and digits of the email's local part (at most 15). Offline XUID (`0xE000` plus 48 random
bits) and the XenonKey (16 random bytes) are created once per account and console and stored (`xuacs.json`, 0600).
0x63F is the enrol point: `SignInService.Link` claims `x360-console` (the 12 digits of the gateway session, from
the `X-X360-Account` header the gateway sets) and `x360` (XUID hex, gamertag as public code) for the account; a
console or profile owned by another account is refused with 403 and nothing is issued.

## Gateway service transport (`x360-gateway`)

After the SG handshake XAM runs TCP inside the secure channel: "code 3" datagrams (SPI byte 0 = `pad<<5 | 3`,
16-bit ports, 3DES-CBC block, 12 clear TCP header bytes, counter, 10-byte ICV; layout in
`private notes`, code in `internal/gateway/tcp.go`). The gateway is the passive
end of that connection (`internal/gateway/transport.go`): SYN -> SYN-ACK (MSS 1264, random ISN, window 0x4030),
the client's HTTP request is reassembled from its data segments (out-of-order held, every segment ACKed), proxied
to the backend for the connection's destination port (`X360_GATEWAY_SERVICE_URLS`, else `X360_GATEWAY_SERVICE_URL`;
path and headers kept, plus `X-X360-Account: <digits>@xbox.com`, the session's console, replacing any client value; `Host` set to the backend, body forwarded; 502/503/400 on
failure) and the response is sent as plain HTTP/1.1 with `Content-Length` and `Connection: close` in segments of
at most 1200 bytes (PSH on the last, window-limited, go-back-N on a duplicate ACK), then a FIN. Client FIN is
ACKed, RST drops the connection. Every segment (ports, flags, seq, ack, length), the HTTP request line and
headers, and the response status are logged at info level. Code 0 control messages are unchanged.

The response length is padded to a multiple of 4 with an `X-Pad` header so no segment needs an ICV filler (see
`tcp.go`). No timer-driven retransmit: a lost segment is resent when the client repeats its ACK or request.

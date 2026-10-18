# Changelog: x360-kdc

## v0.1.0 - 2026-10-16

- 2026-10-16: live verification with Wharf (real 17559 dashboard). MACS (1167 -> reply), XEAS (346 -> reply)
  and XETGS `sg/S0` (841 -> reply) each answered on the first attempt against this server, started with the
  dev keys on 127.0.0.1:18088 and `--nic_udp_port_map='88=18088'`. The security-gateway stand-in accepted the
  `sg/S0` ticket this server issued (same ticket key).
- 2026-10-16: D7 advertises services 1, 20 and 25 (25 = LiveHive `/liveinfo`, XRL request 0x1300, needed right
  after the logon; commit c99de28).
- 2026-10-16: release `v0.1.0`, image `ghcr.io/openpak/x360-kdc` (tags 0.1.0, 0.1, latest) built by the release
  workflow. Deployed on the secondary host `draughts-server` (rootless Podman, UDP 88 redirected to 10088 by
  nftables); listening, not yet used by a console.

## Unreleased

- 2026-10-17: x360-xuacs, the account service for Live service 5 (`internal/xuacs`, `cmd/x360-xuacs`, fourth
  binary in the image): XRL 0x645, 0x64A, 0x608 (RSA-OAEP + 3DES, password checked in the account core), 0x60E,
  0x624, 0x1707 and 0x63F (issues the offline XUID and XenonKey and enrols the console and profile through
  `SignInService.Link`); 0x649 is refused. Raw-field replies, no envelope. Unit-tested with a fake core and a
  client-side 0x608 builder; untested against the applet. Deploy file for the primary, not applied.
- 2026-10-17: gateway `X360_GATEWAY_SERVICE_URLS` (`port=url;port=url`) routes tunnelled connections by destination
  port, `X360_GATEWAY_SERVICE_URL` stays the default; upstream requests carry `X-X360-Account`.
- 2026-10-17: D7 default services are now 1, 20, 25 and 5 (xuacs).
- 2026-10-17: v0.7.3 xuacs: 0x627 XeGetAccountInfoFromPassport (asked by the Account Recovery time-zone step before
  0x63F): gamertag as first name, empty strings, DOB 2000-01-01, country US.

- 2026-10-17: v0.7.5 Download Profile past 0x627: the applet's next step downloads
  `/xedl/ProfileInfo/<CountryId>/CountryInfo.cib` from Live service 11, which D7 did not list, so the console's
  service lookup failed (0x80151100 -> 800704DB, "problem with the credentials"). D7 default adds 11 (deployed
  `X360_KDC_D7_SERVICES=1,20,25,5,11`); x360-xuacs serves the CountryInfo file (US settings, default time zone
  PACIFIC); Traefik routes `/xedl` to it.

- 2026-10-17: v0.7.4 xuacs reconcile loop (startup, then every 60 s): every active account in the core (Identity.ListAccounts,
  keyset pages of 200) gets an active `x360` profile link with its own online XUID (stored or derived by
  `Store.OnlineXUID`), console-less. No `x360-console` link is ever invented (the console subject comes from the
  console certificate); a later 0x63F enrolment finds and reuses the profile link. Accounts that already have an
  active link, or whose XUID is held by another account, are skipped; one failure never stops the pass; logs
  counts only.

- 2026-10-16: LiveHive responses are now XRL "xon" binary bodies (reverse-engineered from the xam.xex schema
  bytecode and response decoder, notes `xon-hive-format.md`): GetLiveConfig = u32 total, u16 chunk count, chunks
  of u16 length + text (little-endian, no NUL), 42 bytes for the default hive; `getnetworkauthorizationlist`
  = u16 entry count (empty list = `00 00`); `Content-Type: xon/19`. The bare NUL-terminated text of the
  previous entry made XAM fail with 0x8007065B. The gateway and liveinfo now log small request bodies as hex
  (the 8-byte request is predicted `06 00 "xenon" 00`).
- 2026-10-16: gateway service transport. Code-3 TCP-over-SA datagrams (`tcp.go`; the ICV verifies and the plaintext
  decodes on the captured client SYNs of run sg6, resealing reproduces them byte for byte), passive TCP with
  SYN-ACK, request reassembly, HTTP proxy to `X360_GATEWAY_SERVICE_URL` and segmented response + FIN
  (`transport.go`). Untested against a live client.
- 2026-10-16: account core identity. `internal/accountcore` is a stdlib gRPC client (Links, Identity.VerifyPassword).
  With `X360_KDC_ACCOUNT_CORE_URL` + `_TOKEN`, MACS refuses only revoked/revoking pairings and core errors;
  consoles the core has not seen stay unowned in the local store and are served normally. Owned consoles cache
  the link and account. `SignInService` enrols on user sign-in (console + XUID links, gamertag); the TGS user
  path is a logged TODO until the request is captured. Unset: behaviour unchanged (development only).
- 2026-10-16: LiveHive config endpoint, `internal/liveinfo` and `cmd/x360-liveinfo` (third binary in the image):
  `/liveinfo/GetLiveConfig.ashx` serves the `key=value;...` NUL-terminated hive (`^` escaping, size < 0x7531,
  `LiveHivePollFrequencyInMinutes`, `SMRevision` omitted unless configured); `getnetworkauthorizationlist.ashx`
  answers an empty hive (unverified). Requests logged with User-Agent and X-Schema-Ver. Not yet reachable: the
  SG transport for service 25 is not done.

- 2026-10-16: first cut. Go port of OpenPak's Python oracle for the Xbox 360 Kerberos stages on UDP 88:
  MACS console authentication (OAEP secret, CA PSS and console PKCS#1 signatures, CE HMAC, encrypted
  timestamp; account record in padata 0xCB), XEAS machine-account exchange (stored account with
  provenance, CE, 5-minute timestamp; authenticated TGT) and the XETGS `sg/S0` TGS-REQ (own-ticket check,
  authenticator with body MD5, D6 under D(session, nonce); D7 service record with services 1 and 20 at a
  configurable SG address). JSON account store (0600, atomic) and 16-byte ticket key file. Unit tests, a
  synthetic end-to-end exchange with every rejection path, and replay of the live captures with the dev
  keys. Not deployed, no tag, not yet tried by the emulator itself.

- 2026-10-17: v0.8.0 Live sign-in of a downloaded profile (XamUserLogon 0x514B4). x360-xuacs serves the
  Windows Live ID login XAM runs before the user's Kerberos exchange, on its own TLS listener
  (`X360_XUACS_TLS_ADDR`, leaves for nexus.passport.com / login.live.com from a CA in the state dir; XAM checks
  name and dates only, RSA key exchange, AES-CBC): FederationMetaData.xml, openid-configuration,
  deviceaddcredential.srf, RST2.srf (device token) and oauth20_token.srf (password grant checked in the account
  core, refresh grant), issuing an HMAC-signed access ticket that the console sends to XEAS in padata 0xDA.
  Internal API (`X360_XUACS_INTERNAL_ADDR`/`_KEY`): profile XenonKey by console + gamertag, WLID ticket check;
  0x63F now stores the gamertag with the profile. x360-kdc answers the user AS-REQ (padata 0x82 parent TGT,
  2, 0xCE, 0xDA; K_u = HMAC-MD5(HMAC-MD5(XenonKey, "signaturekey\0"), MD5(00 04 00 00 || parent session key)))
  with a user TGT whose authorization-data names the console and the authorised users; the TGS accepts D6
  user ids that the chain authorised (D7 user words 0) instead of refusing them; the gateway accepts those
  tickets and passes `X-X360-Users` upstream. Unit-tested only.

- 2026-10-17: v0.8.1 presence. The gateway publishes every user signed in on a live session (users from the
  user-logon ticket) to the account core: `Sessions.RegisterSession` namespace `xbox360`, title empty (signed
  in, not in a game), endpoint `x360:<online xuid>`, lease 60 s renewed every 15 s, expired when no live
  session carries the user or the console has been silent for 3 minutes. Every platform's friend list reads it
  through `GetPresence` ("Xbox 360"). Wharf: NtDeleteFile (profile replace in Download Profile).

- 2026-10-17: v0.8.2 the WLID TLS handshake asks Live service 12 (`/xsig/ValidateCertificate.ashx`, XRL 0xC0B) to
  validate the server leaf mid-handshake; without 12 in D7 XAM closed the socket silently (80151103). D7 default
  adds 12, x360-xuacs answers (u32 HRESULT 0 + u64 FILETIME cache expiry for leaves its WLID CA issued,
  0x80090325 otherwise), Traefik routes `/xsig`. Leaf notBefore backdated 48 h; TLS logs the ClientHello and
  per-connection byte counts.

- 2026-10-17: v0.8.3 the 17559 user AS-REQ carried an empty gamertag (`cname=@xbox.com`), so the profile lookup
  refused it and the console timed out (80151909). With no gamertag, x360-xuacs lists every profile issued on the
  console and the KDC takes the one whose K_u opens the encrypted timestamp (the WLID ticket check still binds it
  to the account).

- 2026-10-17: v0.8.4 padata 0xDA's length prefix is little-endian on the wire (live: 91-byte plaintext, `59 00`
  + the 89-byte ticket); the KDC read it big-endian and refused "DA length". Both orders accepted, LE first.

- 2026-10-17: v0.8.5 gateway: after the user TGS the console sends a 544-byte secure-channel message with 0x40
  in the first SPI byte (it authenticates under the session keys); it was refused as a foreign SPI, the console
  tore the session down and the sign-in failed with 800704DB. 0x40 is accepted as a flag like 0x80 and logged.

- 2026-10-17: v0.8.6 gateway answers 0x0553 (the user logon's new sg ticket for the open session: u32 flags, u64
  token, AP-REQ) with 0x0653 echoing the token (XAM FUN_81754C38 waits for exactly that; no key change). Without
  it XAM retried, closed the session (0x0053 reason 8) and the sign-in ended in 800704DB. The session takes the
  users from the ticket (presence). SPI: only bytes 1..3 identify the session, byte 0 carries per-packet flags.

- 2026-10-18: v0.8.7 gateway: SPI byte 0 of a data packet is the pad length (pad<<5; the console's 0x80/0x40/0x20 are
  4/2/1 pad bytes, not flags). XAM passes plaintext-minus-pad to its dispatcher and drops a message whose header
  length differs, so every padded server message (0x0153, 0x0953, 0x0653) was authenticated but never acted on; the
  console kept resending 0x0553, closed with reason 8 and the sign-in ended in 800704DB. seal() now sets byte 0.

- 2026-10-18: v0.8.8 gateway logs the first bytes a client sends on a non-HTTP tunnelled TCP connection ("stream rx")
  and keeps it open. After the 0x0653 the console's XLive worker connects a TCP stream to Live service 26
  (FUN_818f07a8) and fails the whole logon with 800704DB when the service is not in D7 (0x80151100). D7 now lists 26.

- 2026-10-18: v0.8.9 gateway answers the service-26 stream (stream.go). The console's first message after the user
  logon is command 100 (24-byte LE header + u16 count + online XUID, 34 bytes); the XLive state machine
  (FUN_818d02b8) accepts command+201 with the same id, total length 28 and a 4-byte status 0. Without a reply it
  retried after 25 s and failed with 8015820A.

- 2026-10-18: v0.8.10 xuacs: /xpnfront/xpresence.srf (Live service 1), the request the console sends after the
  service-26 stream is up; it was a 404 from the default backend and ended the logon with 807B0194. The body is
  logged in full and answered with an empty 200 while the format is decoded.

- 2026-10-18: v0.8.11 xuacs: /xpnfront/xpresence.srf answers request 0x2 ("presence alive", one entry per signed-in
  user, 32-byte header + msg_len) with one element per entry: the header with msg_len 16 and the same seq, then
  result 0, the console's friend/block list versions echoed, zero counts. The console matches elements to users by
  seq; the empty 200 left it with none (0x80150007). Format from the schema-interpreter analysis
  (scratch/wharf/kdcstub/notes/xrl-schema-opcodes.md).

- 2026-10-18: v0.8.12 xuacs: /xbos/GetRevocationList.ashx (Live service 21, request 0x918), an empty revocation list;
  D7 lists service 21. With the xpresence reply accepted the console's user logon stalled with no error: its
  post-logon revocation-list fetch (FUN_818cd740 -> FUN_81825530) had no service 21 to go to.

- 2026-10-18: v0.8.13 xuacs: /xstats/*.ashx (Live services 34 and 35) answer with empty-success replies; D7 lists 34
  and 35. With the title-sync event fixed in Wharf the console's post-logon sync looked up service 35 and failed
  locally with 800704DB (0x80151100: not in D7).

- 2026-10-18: v0.8.14 merges the permanent core-owned handles work (605c55e: GetAccount field 9 is the permanent
  handle; enrollment and LinkProfile use it; the KDC key lookup verifies the stored profile against the core
  account and canonical handle; docs/handles.md) with the sign-in line above (v0.8.7-v0.8.13) into one release.
  All x360 containers (kdc, gateway, xuacs, liveinfo) run this image from the registry; the local
  unified-handle image is retired.

- 2026-10-18: v0.9.0 split into one repository and one image per service. This repository now builds only the
  KDC (`ghcr.io/openpak/x360-kdc`); the gateway (x360-gateway), account service (x360-xuacs) and LiveHive
  endpoint (x360-liveinfo) moved to their own repositories with their history, and the shared packages
  (`kdc`, `accountcore`, `config`, `der`, `rc4hmac`, the new `wire`) to `x360-common`, consumed through a
  `replace` and a committed `vendor/` like nx-common. The xexds and notice units moved to their repositories.

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

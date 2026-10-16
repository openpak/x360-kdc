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

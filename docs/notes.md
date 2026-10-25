# Notes: x360-kdc

> **Repository layout (2026-10-18).** This repository was one monorepo for the KDC, gateway, account
> service and LiveHive endpoint. Each is now its own repository and image, sharing the Go library
> [`x360-common`](../../x360-common): [`x360-kdc`](../) (this one), [`x360-gateway`](../../x360-gateway),
> [`x360-xuacs`](../../x360-xuacs), [`x360-liveinfo`](../../x360-liveinfo). Text below that describes the
> gateway, xuacs or liveinfo internals now lives in their repositories; history was kept in each.

## Microsoft's hosts

Microsoft's hosts no longer answer, so a real 360 fails at "Xbox Live" in **Network Settings -> Test Xbox Live
Connection** and the dashboard shows "Your console can't connect to Xbox Live". With this service the firmware
authenticates, installs an account and gets as far as the security-gateway handshake, which is the next thing
to build (not here).

## Naming

Naming rule: every OpenPak Xbox 360 service is called `x360-<thing>`. Siblings: [`x360-xexds`](../../x360-xexds),
[`x360-notice`](../../x360-notice).

## Architecture

Architecture: **a real Xbox 360 and the Wharf emulator hit the same endpoint.** Both resolve the three names;
DNS redirects them to this service (OpenPak's resolver for consoles, `nic_dns_hosts` for Wharf). There is no
emulator-only path, port or packet. The one emulator-specific value is the security-gateway address the TGS
reply advertises (`X360_KDC_SG_ADDRESS`, see below).

## Status snapshots

Status, 2026-10-16: a port of OpenPak's Python oracle (`private notes`), which
the firmware accepted live on its first attempt for all three stages (MACS 1167 -> 545 bytes, XEAS 353 -> 550,
TGS 841 -> 772; `private notes`). This Go server replays those captures in its tests:
every request verifies with the real keys, every reply has the same DER shape as the accepted one, and the
deterministic records (account record, service record) are byte-identical.

Release and deployment, 2026-10-16: tag `v0.1.0`, image `ghcr.io/openpak/x360-kdc` (tags `0.1.0`, `0.1`,
`latest`) built by the release workflow. Deployed on the secondary host `draughts-server` (HOST_IP)
as a rootless Podman 5.7 quadlet (see "Deployment"). No console has used it yet, and no OpenPak DNS entry
points the three names at it yet.

## Enrolment

**Enrol on user sign-in** (`internal/accountcore.SignInService`, the service layer; the wire trigger is not
captured yet). `SignIn` verifies the OpenPak email and password with `Identity.VerifyPassword` (adapter
namespace `x360`, purpose `console_login`; two-factor accounts fail closed, banned or deleted accounts are
refused), then `ReserveLink` + `ActivateLink` for `x360-console`/console digits with that account, then the same
for `x360`/XUID as 16 hex digits and `SetLinkPublicCode` = gamertag. A console or profile held by another account
is refused (`ErrConsoleOwned`, `ErrUserOwned`) and nothing is changed; repeating it for the same account is a
no-op. The TGS user path (`tgs.go`, non-zero D6 user ids) logs `user_xuids` and still refuses with a TODO: where
the firmware carries the credentials needs a capture of XamUserLogon; no bytes are guessed.

## Layout

`cmd/x360-kdc` main (also `cmd/x360-gateway`, `cmd/x360-liveinfo`, `cmd/x360-xuacs`); `internal/xuacs`; `internal/config`; `internal/der` (the DER subset, nonce rule); `internal/rc4hmac` (etype 23
and `D(K,N)`); `internal/kdc` (`Handler.Handle` is the whole protocol as a function from datagram to reply,
`as.go` MACS/XEAS, `tgs.go` XETGS, `cert.go` certificate and key loading, `accounts.go` the store, `reply.go`
the encoders, `Server` the receive loop). Go standard library only. License: AGPL-3.0-only, like the rest of the
OpenPak servers.

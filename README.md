# x360-kdc

OpenPak's Xbox 360 Kerberos endpoint: the three exchanges the 360 firmware (17559) runs over **UDP port 88**
when it signs in to Xbox Live, served by one process on one socket:

| Stage | Hostname the firmware resolves | Realm | What it is |
|---|---|---|---|
| MACS | `xemacs.xboxlive.com` | `MACS.XBOX.COM` | console authentication: RSA/CA-signed console certificate, issues the machine account (padata 0xDB in, 0xCB out) |
| XEAS | `xeas.xboxlive.com` | `XBOX.COM` | machine-account AS exchange with the issued key, returns a TGT (padata 0xD8) |
| XETGS | `xetgs.xboxlive.com` | `XBOX.COM` | TGS-REQ for the security gateway `sg/S0`, returns the service record (padata 0xD6 in, 0xD7 out) |

Microsoft's hosts no longer answer, so a real 360 fails at "Xbox Live" in **Network Settings -> Test Xbox Live
Connection** and the dashboard shows "Your console can't connect to Xbox Live". With this service the firmware
authenticates, installs an account and gets as far as the security-gateway handshake, which is the next thing
to build (not here).

Naming rule: every OpenPak Xbox 360 service is called `x360-<thing>`. Siblings: [`x360-xexds`](../x360-xexds),
[`x360-notice`](../x360-notice).

Architecture: **a real Xbox 360 and the Wharf emulator hit the same endpoint.** Both resolve the three names;
DNS redirects them to this service (OpenPak's resolver for consoles, `nic_dns_hosts` for Wharf). There is no
emulator-only path, port or packet. The one emulator-specific value is the security-gateway address the TGS
reply advertises (`X360_KDC_SG_ADDRESS`, see below).

Status, 2026-10-16: a port of OpenPak's Python oracle (`scratch/wharf/kdcstub/{kdc,xeas,xetgs}.py`), which
the firmware accepted live on its first attempt for all three stages (MACS 1167 -> 545 bytes, XEAS 353 -> 550,
TGS 841 -> 772; `scratch/wharf/run/logs/kdc-xetgs2/`). This Go server replays those captures in its tests:
every request verifies with the real keys, every reply has the same DER shape as the accepted one, and the
deterministic records (account record, service record) are byte-identical.

Live verification, 2026-10-16: Wharf (the real 17559 dashboard) completed **MACS** (1167-byte request, reply
returned), **XEAS** (346 -> reply) and **XETGS `sg/S0`** (841 -> reply) against this server on the first attempt
of each. The security-gateway stand-in then accepted the `sg/S0` ticket this server issued (same ticket key).
D7 now advertises services **1, 20 and 25** (25 = LiveHive `/liveinfo`, XRL request 0x1300, needed right after
the logon; commit c99de28). Not yet tried by a real console.

Release and deployment, 2026-10-16: tag `v0.1.0`, image `ghcr.io/openpak/x360-kdc` (tags `0.1.0`, `0.1`,
`latest`) built by the release workflow. Deployed on the secondary host `draughts-server` (145.241.228.207)
as a rootless Podman 5.7 quadlet (see "Deployment"). No console has used it yet, and no OpenPak DNS entry
points the three names at it yet.

## Protocol

Everything below is derived from the firmware's own code by OpenPak (clean room; see
[`docs/clean-room-policy.md`](../docs/clean-room-policy.md)). Source of truth with offsets and firmware
addresses: [`docs/xbox360/wharf-base-plan.md`](../docs/xbox360/wharf-base-plan.md), the three dated
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

## Run

```sh
cp example.env .env
set -a; source .env; set +a
go run ./cmd/x360-kdc            # listens on UDP :88 (privileged; see below)
```

The MACS private key and the console CA public key are required and must come from the same provisioning as
the consoles'/emulator's trust material (next section). The account store and the ticket key are created on
demand (mode 0600). Port 88 is privileged: the container image carries `cap_net_bind_service`; a bare binary
needs root, `setcap cap_net_bind_service=+ep`, or a high port with a redirect in front.

### Wharf test

Wharf (OpenPak's Xbox 360 emulator, `../emulators/wharf`) maps the guest's `10.0.2.2:88` to a host port and
redirects the hostnames with its own flags. Start the server on the mapped port with the dev material:

```sh
K=../scratch/wharf/keys
X360_KDC_ADDR=127.0.0.1:18088 \
X360_KDC_XMACS_KEY=$K/xmacs-dev-private.pem \
X360_KDC_CONSOLE_CA=$K/console-ca-public.pem \
X360_KDC_ACCOUNTS=$K/x360-dev-accounts.json \
X360_KDC_TICKET_KEY=$K/x360-ticket-key.bin \
go run ./cmd/x360-kdc
```

Then launch Wharf the way `../scratch/wharf/w-live-test.sh` does (the x360-xexds and x360-notice stand-ins
answer the other names):

```sh
bash scratch/wharf/w-start.sh \
  --nic_dns_hosts='xemacs.xboxlive.com=10.0.2.2;xeas.xboxlive.com=10.0.2.2;xetgs.xboxlive.com=10.0.2.2;xexds.xboxlive.com=10.0.2.2;xncsi.xboxlive.com=10.0.2.2;notice.xbox.com=10.0.2.2' \
  --nic_tcp_port_map='443=18443;80=18080' \
  --nic_udp_port_map='88=18088' \
  --console_ca_key=~/REPOS/Openpak/scratch/wharf/keys/console-ca-key.txt
```

`--nic_udp_port_map='88=18088'` is what sends the guest's port-88 datagrams to this server;
`--console_ca_key` gives the emulated console the CA-signed identity the server verifies. Only one process
can hold 127.0.0.1:18088: stop the Python oracle (`kdcstub/xetgs.py`) first. Expected log: one `answered
kind=MACS`, one `kind=XEAS`, one `kind=TGS`, then the firmware moves on to the SG step (`XeCryptBnDwLeDhModExp`
in the guest log), which no server implements yet. The default `X360_KDC_SG_ADDRESS=10.0.2.2` is right only
for this setup.

## Deployment

Secondary host `draughts-server` (145.241.228.207), rootless Podman 5.7, `ubuntu` user. Quadlet
`~/.config/containers/systemd/openpak-x360-kdc.container`:

- `Network=host`, `ReadOnly`, `NoNewPrivileges`, `DropCapability=ALL` plus `AddCapability=NET_BIND_SERVICE`.
  The image binary carries the `cap_net_bind_service` file capability, and exec fails with EPERM when that
  capability is not permitted, even though the service listens on 10088.
- `UserNS=keep-id:uid=100,gid=101` (the image's `app` user).
- Volumes: `~/openpak/deploy/x360-kdc/secrets:/run/secrets:ro` (`xmacs-dev-private.pem`,
  `console-ca-public.pem`, mode 0600) and `~/openpak/deploy/x360-kdc/state:/var/lib/x360-kdc:rw`
  (`accounts.json`, `ticket-key.bin`).
- Environment: `X360_KDC_ADDR=:10088`, `X360_KDC_SG_ADDRESS=145.241.228.207`. `AutoUpdate=registry`.

Rootless Podman cannot bind UDP 88 in the host network namespace. `/etc/openpak/x360-kdc.nft` (own nft table
`ip x360kdc`, `udp dport 88 redirect to :10088` in prerouting) and `/etc/openpak/x360-kdc-fw.sh` front it.
The script runs from `openpak-x360-kdc-fw.service` (oneshot, enabled) and inserts the INPUT accept for 10088
before the first REJECT, idempotently. The listener is verified; the dev key material above is what it runs
with until production provisioning exists.

To point Wharf at the deployed server instead of a local one, use `nic_dns_hosts=...=145.241.228.207` and
no port map.

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
Every request is logged at info level (method, path, headers, small body as hex); the gateway logs the same
body hex for Content-Length up to 64. Config: `X360_LIVEINFO_ADDR` (default `:25`, TCP),
`X360_LIVEINFO_SMREVISION`, `X360_LIVEINFO_POLL_MINUTES` (default 120), `X360_LIVEINFO_DEBUG`. Code:
`internal/liveinfo`, `cmd/x360-liveinfo`.

`X360_LIVEINFO_HIVE_EXTRA` adds keys to the hive as `key=value` pairs separated by `;` (values may contain
`/`, `:` and `.`; `^`, `;` and `=` are escaped). The pairs are emitted after the known keys, sorted by key;
empty keys, pairs without `=` and duplicate keys are rejected at startup. The point is to advertise OpenPak
service roots: the dash reads `LiveServiceUrl.*` and `*UriRoot` keys from the hive to find the other services.
Nothing is set by default; the example value is in `example.env`.

## Dev key material

Never commit keys. The dev set lives in `../scratch/wharf/keys/` (mode 0600 where private) and was made with
openssl; to regenerate from scratch:

```sh
# MACS key pair: the server holds the private key, the console/emulator carries the public key.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out xmacs-dev-private.pem
openssl pkey -in xmacs-dev-private.pem -pubout -out xmacs-dev-public.pem
# Console CA: signs each console's 424-byte certificate; the server trusts only this public key.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out console-ca-private.pem
openssl pkey -in console-ca-private.pem -pubout -out console-ca-public.pem
# Ticket key: 16 random bytes (the server also creates it itself when the file is missing).
head -c 16 /dev/urandom > x360-ticket-key.bin && chmod 600 x360-ticket-key.bin
```

The emulator-side formats (the XMACS public key as `xmacs-dev-public.xe.bin`, the CA private key as the
`--console_ca_key` n/d hex file, and the per-console RSA-1024 identity plus its CA-signed certificate) are
produced by the Wharf tooling, not by this repo. A real console must be provisioned with a certificate signed
by the same CA and firmware that carries the same XMACS public key; the server cannot and does not accept
Microsoft-signed certificates. Rotating the CA invalidates every stored account (their certificates stop
verifying); rotating the ticket key only invalidates tickets in flight. The account store is plain JSON
(`{"<digits>@xbox.com": {certificate, account, console_signature_verified, issued_at}}`); delete an entry to
force re-provisioning.

## Tests

```sh
go test ./...                                   # DER, RC4-HMAC, store, and a full synthetic MACS -> XEAS -> TGS exchange
X360_KDC_TESTKEYS=../scratch/wharf/keys go test ./...   # plus replay of the live captures in ../scratch/wharf/run/logs
go vet ./... && gofmt -l .
```

The synthetic test generates its own CA, XMACS and console keys, builds the three requests the way the
firmware does and decodes the replies the way XAM's parser does (nonce echo, key sizes, 108 -> 84 and
208 -> 184 records, ticket <= 1024 bytes), then checks every rejection: each tampered byte region of the
console block, another CA, wrong cname, tampered CE/timestamp/authenticator/D6, modified request body, foreign
or expired ticket, stale authenticator, user ids present, missing provenance. The replay test works on a copy
of the account store and sets the clock to each capture's time, so the saved datagrams validate; on this
workstation run tests with `TMPDIR=../scratch/tmp` (never /tmp).

## Gateway service transport (`x360-gateway`)

After the SG handshake XAM runs TCP inside the secure channel: "code 3" datagrams (SPI byte 0 = `pad<<5 | 3`,
16-bit ports, 3DES-CBC block, 12 clear TCP header bytes, counter, 10-byte ICV; layout in
`scratch/wharf/kdcstub/notes/svc-open-layout.md`, code in `internal/gateway/tcp.go`). The gateway is the passive
end of that connection (`internal/gateway/transport.go`): SYN -> SYN-ACK (MSS 1264, random ISN, window 0x4030),
the client's HTTP request is reassembled from its data segments (out-of-order held, every segment ACKed), proxied
to `X360_GATEWAY_SERVICE_URL` (path and headers kept, `Host` set to the backend, body forwarded; 502/503/400 on
failure) and the response is sent as plain HTTP/1.1 with `Content-Length` and `Connection: close` in segments of
at most 1200 bytes (PSH on the last, window-limited, go-back-N on a duplicate ACK), then a FIN. Client FIN is
ACKed, RST drops the connection. Every segment (ports, flags, seq, ack, length), the HTTP request line and
headers, and the response status are logged at info level. Code 0 control messages are unchanged.

The response length is padded to a multiple of 4 with an `X-Pad` header so no segment needs an ICV filler (see
`tcp.go`). No timer-driven retransmit: a lost segment is resent when the client repeats its ACK or request.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `X360_KDC_ADDR` | no | `:88` | UDP listen address |
| `X360_KDC_XMACS_KEY` | yes | | RSA-2048 private key PEM (PKCS#8 or PKCS#1) for the MACS OAEP block |
| `X360_KDC_CONSOLE_CA` | yes | | RSA-2048 public key PEM, the console certificate trust anchor |
| `X360_KDC_ACCOUNTS` | no | `x360-accounts.json` | machine-account store, written 0600 via rename |
| `X360_KDC_TICKET_KEY` | no | `x360-ticket-key.bin` | 16-byte ticket key, created 0600 when missing |
| `X360_KDC_SG_ADDRESS` | no | `10.0.2.2` | IPv4 advertised as the security gateway in the D7 record; the default fits only a local Wharf test |
| `X360_KDC_ACCOUNT_CORE_URL` | production: yes | | account core gRPC listener (`http://host:7000`, cleartext HTTP/2, or `https://`). Set together with the token or not at all |
| `X360_KDC_ACCOUNT_CORE_TOKEN` | with URL | | the core's internal key (`x-internal-key`) |
| `X360_KDC_DEBUG` | no | `false` | debug-level logging |
| `X360_GATEWAY_SERVICE_URL` | no | `http://openpak-x360-liveinfo:10025` | x360-gateway: HTTP backend the service transport proxies to (`http://145.241.199.19` on the deployed secondary) |

**Production must set the account-core variables.** The core cannot hold a device without an owner, so a console
has two states:

- **Pending / unowned**: the core has no `x360-console` link for it (or only a pending reservation). MACS, XEAS
  and XETGS still serve it from the local store, so a CA-verified console always gets its machine account, TGT
  and `sg/S0` ticket. The MACS log line says `console=unowned`.
- **Owned**: an `active` link (namespace `x360-console`, subject = the 12 console digits) exists. The record
  caches `core_link_id`/`core_account_id` and the log carries `core_link`/`core_account`.

Only a link the core reports `revoking` or `revoked`, or a core error or timeout (10 s), stops MACS (no reply,
nothing cached). Without the variables the local store alone decides: development only, warned at start.

**Enrol on user sign-in** (`internal/accountcore.SignInService`, the service layer; the wire trigger is not
captured yet). `SignIn` verifies the OpenPak email and password with `Identity.VerifyPassword` (adapter
namespace `x360`, purpose `console_login`; two-factor accounts fail closed, banned or deleted accounts are
refused), then `ReserveLink` + `ActivateLink` for `x360-console`/console digits with that account, then the same
for `x360`/XUID as 16 hex digits and `SetLinkPublicCode` = gamertag. A console or profile held by another account
is refused (`ErrConsoleOwned`, `ErrUserOwned`) and nothing is changed; repeating it for the same account is a
no-op. The TGS user path (`tgs.go`, non-zero D6 user ids) logs `user_xuids` and still refuses with a TODO: where
the firmware carries the credentials needs a capture of XamUserLogon; no bytes are guessed.

Deployment: the KDC on the secondary host reaches the core through the ZeroTier forwarder,
`X360_KDC_ACCOUNT_CORE_URL=http://10.212.63.196:20001`, with `X360_KDC_ACCOUNT_CORE_TOKEN` taken from the box's
shared env file (the core's internal key; never print or commit it).

## Layout

`cmd/x360-kdc` main; `internal/config`; `internal/der` (the DER subset, nonce rule); `internal/rc4hmac` (etype 23
and `D(K,N)`); `internal/kdc` (`Handler.Handle` is the whole protocol as a function from datagram to reply,
`as.go` MACS/XEAS, `tgs.go` XETGS, `cert.go` certificate and key loading, `accounts.go` the store, `reply.go`
the encoders, `Server` the receive loop). Go standard library only. License: AGPL-3.0-only, like the rest of the
OpenPak servers. Releases: tag `v*.*.*` publishes `ghcr.io/openpak/x360-kdc` and deployed hosts auto-update
from it, so nothing is tagged until a deploy is wanted.

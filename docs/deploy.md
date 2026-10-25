# Deploy: x360-kdc

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
K=private notes
X360_KDC_ADDR=127.0.0.1:18088 \
X360_KDC_XMACS_KEY=$K/xmacs-dev-private.pem \
X360_KDC_CONSOLE_CA=$K/console-ca-public.pem \
X360_KDC_ACCOUNTS=$K/x360-dev-accounts.json \
X360_KDC_TICKET_KEY=$K/x360-ticket-key.bin \
go run ./cmd/x360-kdc
```

Then launch Wharf the way `private notes` does (the x360-xexds and x360-notice stand-ins
answer the other names):

```sh
bash private notes \
  --nic_dns_hosts='xemacs.xboxlive.com=10.0.2.2;xeas.xboxlive.com=10.0.2.2;xetgs.xboxlive.com=10.0.2.2;xexds.xboxlive.com=10.0.2.2;xncsi.xboxlive.com=10.0.2.2;notice.xbox.com=10.0.2.2' \
  --nic_tcp_port_map='443=18443;80=18080' \
  --nic_udp_port_map='88=18088' \
  --console_ca_key=private notes
```

`--nic_udp_port_map='88=18088'` is what sends the guest's port-88 datagrams to this server;
`--console_ca_key` gives the emulated console the CA-signed identity the server verifies. Only one process
can hold 127.0.0.1:18088: stop the Python oracle (`kdcstub/xetgs.py`) first. Expected log: one `answered
kind=MACS`, one `kind=XEAS`, one `kind=TGS`, then the firmware moves on to the SG step (`XeCryptBnDwLeDhModExp`
in the guest log), which no server implements yet. The default `X360_KDC_SG_ADDRESS=10.0.2.2` is right only
for this setup.

## Deployment

Secondary host `draughts-server` (HOST_IP), rootless Podman 5.7, `ubuntu` user. Quadlet
`~/.config/containers/systemd/openpak-x360-kdc.container`:

- `Network=host`, `ReadOnly`, `NoNewPrivileges`, `DropCapability=ALL` plus `AddCapability=NET_BIND_SERVICE`.
  The image binary carries the `cap_net_bind_service` file capability, and exec fails with EPERM when that
  capability is not permitted, even though the service listens on 10088.
- `UserNS=keep-id:uid=100,gid=101` (the image's `app` user).
- Volumes: `~/openpak/deploy/x360-kdc/secrets:/run/secrets:ro` (`xmacs-dev-private.pem`,
  `console-ca-public.pem`, mode 0600) and `~/openpak/deploy/x360-kdc/state:/var/lib/x360-kdc:rw`
  (`accounts.json`, `ticket-key.bin`).
- Environment: `X360_KDC_ADDR=:10088`, `X360_KDC_SG_ADDRESS=HOST_IP`. `AutoUpdate=registry`.

Rootless Podman cannot bind UDP 88 in the host network namespace. `/etc/openpak/x360-kdc.nft` (own nft table
`ip x360kdc`, `udp dport 88 redirect to :10088` in prerouting) and `/etc/openpak/x360-kdc-fw.sh` front it.
The script runs from `openpak-x360-kdc-fw.service` (oneshot, enabled) and inserts the INPUT accept for 10088
before the first REJECT, idempotently. The listener is verified; the dev key material above is what it runs
with until production provisioning exists.

To point Wharf at the deployed server instead of a local one, use `nic_dns_hosts=...=HOST_IP` and
no port map.

## LiveHive config

Every request is logged at info level (method, path, headers, small body as hex); the gateway logs the same
body hex for Content-Length up to 64. Config: `X360_LIVEINFO_ADDR` (default `:25`, TCP),
`X360_LIVEINFO_SMREVISION`, `X360_LIVEINFO_POLL_MINUTES` (default 120), `X360_LIVEINFO_DEBUG`. Code:
`internal/liveinfo`, `cmd/x360-liveinfo`.

`X360_LIVEINFO_HIVE_EXTRA` adds keys to the hive as `key=value` pairs separated by `;` (values may contain
`/`, `:` and `.`; `^`, `;` and `=` are escaped). The pairs are emitted after the known keys, sorted by key;
empty keys, pairs without `=` and duplicate keys are rejected at startup. The point is to advertise OpenPak
service roots: the dash reads `LiveServiceUrl.*` and `*UriRoot` keys from the hive to find the other services.
Nothing is set by default; the example value is in `example.env`.

## Account service config

Config: `X360_XUACS_ADDR` (default `:5`), `X360_XUACS_RSA_KEY` (RSA-2048 PEM, generated 0600 when missing; default
`<state>/rsa-key.pem`), `X360_XUACS_ACCOUNT_CORE_URL` and `_TOKEN` (both required), `X360_XUACS_STATE` (default
`x360-xuacs-state`), `X360_XUACS_MAX_SKEW`, `X360_XUACS_DEBUG`. Every request is logged (path, user agent, headers,
body hex when 64 bytes or less) and every response status. Deploy file (not applied):
`deploy/primary/openpak-x360-xuacs.container` plus the Traefik router in `traefik-x360-fragment.yml`.

## Dev key material

Never commit keys. The dev set lives in `private notes` (mode 0600 where private) and was made with
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
| `X360_GATEWAY_SERVICE_URLS` | no | | x360-gateway: per destination port backends, `port=url;port=url` (e.g. `80=http://PROD_HOST;5=http://PROD_HOST:10005`); ports not listed use `X360_GATEWAY_SERVICE_URL` |
| `X360_GATEWAY_SERVICE_URL` | no | `http://openpak-x360-liveinfo:10025` | x360-gateway: HTTP backend the service transport proxies to (`http://PROD_HOST` on the deployed secondary) |

**Production must set the account-core variables.** The core cannot hold a device without an owner, so a console
has two states:

- **Pending / unowned**: the core has no `x360-console` link for it (or only a pending reservation). MACS, XEAS
  and XETGS still serve it from the local store, so a CA-verified console always gets its machine account, TGT
  and `sg/S0` ticket. The MACS log line says `console=unowned`.
- **Owned**: an `active` link (namespace `x360-console`, subject = the 12 console digits) exists. The record
  caches `core_link_id`/`core_account_id` and the log carries `core_link`/`core_account`.

Only a link the core reports `revoking` or `revoked`, or a core error or timeout (10 s), stops MACS (no reply,
nothing cached). Without the variables the local store alone decides: development only, warned at start.

Deployment: the KDC on the secondary host reaches the core through the ZeroTier forwarder,
`X360_KDC_ACCOUNT_CORE_URL=http://10.212.63.196:20001`, with `X360_KDC_ACCOUNT_CORE_TOKEN` taken from the box's
shared env file (the core's internal key; never print or commit it).

## Release

Releases: tag `v*.*.*` publishes `ghcr.io/openpak/x360-kdc` and deployed hosts auto-update
from it, so nothing is tagged until a deploy is wanted.

# x360-kdc deploy recipes

The gateway, xuacs, liveinfo, xexds and notice units now live in their own repositories
(`deploy/` there); this directory keeps the KDC's units. The overview below is historical.

Copies of the live Xbox 360 service units, nftables redirects and helper scripts,
kept here so the deployment can be rebuilt from the repo. Secrets and state are
never in this directory.

Layout:

- `secondary/` - host HOST_IP
- `primary/` - host PROD_HOST

## What runs where

### Secondary (HOST_IP)

- **x360-kdc**: Kerberos-style KDC for `xemacs/xeas/xetgs.xboxlive.com`. The 360
  dials UDP 88. Rootless podman cannot bind 88 in the host namespace, so the
  service listens on UDP 10088 and `openpak-x360-kdc-fw.service` redirects 88 to
  10088 (`x360-kdc.nft`, `x360-kdc-fw.sh`). Host networking keeps the console's
  source address.
- **x360-gateway**: security gateway (SG). Shares public UDP 3074 with
  xb-gateway. New flows whose payload starts `00 00 00 00 02 58` (SG initiation
  chunk 0x5802) are redirected to UDP 13075 (`x360-gateway.nft`,
  `x360-gateway-fw.sh`). The conntrack timeout for those flows is 1 h after the
  last reply (`replied: 3600`, `unreplied: 600`), because later datagrams carry
  an SPI and cannot be matched by payload.
- **x360-xexds**: XEXDS probe endpoint. Shares UDP 3074 with xb-gateway. New
  flows whose payload starts `01 00 00 00` are redirected to UDP 13074
  (`x360-xexds.nft`, `x360-xexds-fw.sh`). Everything else still reaches xb-gateway.

Each redirect lives in its own nft table (`x360kdc`, `x360gw`, `x360`), so each
one can be deleted without touching the others. Each `*-fw.sh` also inserts an
iptables INPUT accept for its port ahead of the first REJECT.

### Primary (PROD_HOST)

- **x360-liveinfo**: LiveHive endpoint (`/liveinfo/GetLiveConfig.ashx`, Live
  service 25) on port 10025. Traefik routes `PathPrefix(/liveinfo)` on the
  plain-HTTP entrypoint (port 80) to it.
- **x360-xuacs** (file only, not applied): account service (`/xuacs/*.ashx`, Live
  service 5) on port 10005, Traefik `PathPrefix(/xuacs)`. Needs
  `~/openpak/deploy/x360-xuacs/core.env` (account core URL and internal key, mode
  0600) and a writable `~/openpak/deploy/x360-xuacs/state` (uid 100). The KDC must
  list service 5 in D7 (default since this change).
- **x360-notice**: connectivity pages for `xncsi.xboxlive.com` and
  `notice.xbox.com` on port 8080, routed by Traefik on the plain-HTTP entrypoint.
- **Traefik routes**: `traefik-x360-fragment.yml` holds the x360 blocks
  (routers and services for liveinfo, xuacs and notice). They belong in the shared
  `~/openpak/deploy/traefik/dynamic.yml`, not in a separate file.
- **account-core ZeroTier forwarder**: `x360-core-forward.py` (user unit
  `openpak-x360-core-forward.service`) forwards TCP `10.212.63.196:20001` to
  `127.0.0.1:20001`, the account core gRPC. The core only publishes on loopback.
  The live host also has an iptables INPUT accept on `ztfca6tjns` for TCP 20001
  from `10.212.63.175` only (the secondary's ZeroTier address). That rule is in
  the host's live iptables, persisted outside these files
  (`/etc/iptables/rules.v4`). Recreate it if the host is rebuilt.

## Secrets and state on the secondary (not in the repo)

- `~/openpak/deploy/x360-kdc/secrets/`, mounted read-only at `/run/secrets`:
  - `xmacs-dev-private.pem`: private key, read by the KDC as `X360_KDC_XMACS_KEY`
  - `console-ca-public.pem`: console CA (KDC and gateway)
- `~/openpak/deploy/x360-kdc/state/`, mounted at `/var/lib/x360-kdc`: holds
  `ticket-key.bin` and `accounts.json`. The KDC mounts it rw. The gateway mounts
  it ro.
- `~/openpak/deploy/x360-kdc/core.env`, mode 0600, read by the KDC quadlet
  through `EnvironmentFile`. It must define `X360_KDC_ACCOUNT_CORE_URL` and
  `X360_KDC_ACCOUNT_CORE_TOKEN`. Do not commit it.

## Install order

Secondary:

```sh
# copy files
cp secondary/openpak-x360-*.container ~/.config/containers/systemd/
sudo cp secondary/x360-*.nft /etc/openpak/
sudo cp secondary/x360-*-fw.sh /etc/openpak/ && sudo chmod 0755 /etc/openpak/x360-*-fw.sh
sudo cp secondary/openpak-x360-*-fw.service /etc/systemd/system/

# firewall redirects first
sudo systemctl daemon-reload
sudo systemctl enable --now openpak-x360-kdc-fw.service openpak-x360-gateway-fw.service openpak-x360-xexds-fw.service

# services
systemctl --user daemon-reload
systemctl --user start openpak-x360-kdc.service openpak-x360-gateway.service openpak-x360-xexds.service
```

Primary:

```sh
cp primary/openpak-x360-liveinfo.container primary/openpak-x360-notice.container primary/openpak-x360-xuacs.container ~/.config/containers/systemd/
cp primary/x360-core-forward.py ~/openpak/deploy/
cp primary/openpak-x360-core-forward.service ~/.config/systemd/user/
# merge primary/traefik-x360-fragment.yml into ~/openpak/deploy/traefik/dynamic.yml

systemctl --user daemon-reload
systemctl --user enable --now openpak-x360-core-forward.service
systemctl --user start openpak-x360-liveinfo.service openpak-x360-notice.service openpak-x360-xuacs.service
```

Quadlet-generated units take the container name with a `.service` suffix.

## 2026-10-17: the 3074 redirect for the 360 gateway is withdrawn

`secondary/x360-gateway.nft` and `openpak-x360-gateway-fw.service` must NOT be installed: the Xbox 360
initiation cannot be told apart from an original-Xbox user-session initiation at fixed offsets (same
first 12 payload bytes), and the redirect stole those sessions from xb-gateway. XAM also ignores an
extended D7 entry for service 20 with another port (it always dials 3074), so the 360 gateway needs its
own public IPv4 (then `X360_KDC_SG_ADDRESS` points at it and the gateway listens on 3074 there).

## 2026-10-17: the 360 gateway has its own public address

HOST_IP (private 10.0.0.83, on ens3) is attached to the secondary. Table `ip x360gw`
(`secondary/x360-gateway.nft`, applied by `openpak-x360-gateway-fw.service`) redirects UDP 3074 for that
destination address to :13075, where x360-gateway listens. The KDC advertises HOST_IP in the D7
record (`X360_KDC_SG_ADDRESS`). Matching is by destination address only, so xb-gateway on 10.0.0.22 and
the xexds `ip x360` rule are untouched. The old `x360sg` payload-matching table is gone for good. The
UDP-over-TCP tunnel (`deploy/x360-kdc/udp-over-tcp.py` on the box) stays as a fallback only.

# Xbox 360 KDC Server

OpenPak's Xbox 360 KDC Server.

| | |
| --- | --- |
| Network | Xbox 360 (Xbox Live) |
| Role | Kerberos endpoint on UDP 88: console authentication (MACS), machine-account sign-in (XEAS) and the security-gateway ticket (XETGS) |
| Depends on | account core, required in production ([deploy](docs/deploy.md)) |
| Image | `ghcr.io/openpak/x360-kdc` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `xemacs.xboxlive.com` | MACS: console authentication, realm `MACS.XBOX.COM` |
| `xeas.xboxlive.com` | XEAS: machine-account AS exchange, returns a TGT |
| `xetgs.xboxlive.com` | XETGS: TGS-REQ for the security gateway `sg/S0`, returns the service record |

## Run

```sh
cp example.env .env
set -a; source .env; set +a
go run ./cmd/x360-kdc            # listens on UDP :88 (privileged; see docs/deploy.md)
```

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).

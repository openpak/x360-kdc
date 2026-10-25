# Evidence: x360-kdc

## Live verification

Live verification, 2026-10-16: Wharf (the real 17559 dashboard) completed **MACS** (1167-byte request, reply
returned), **XEAS** (346 -> reply) and **XETGS `sg/S0`** (841 -> reply) against this server on the first attempt
of each. The security-gateway stand-in then accepted the `sg/S0` ticket this server issued (same ticket key).
D7 now advertises services **1, 20 and 25** (25 = LiveHive `/liveinfo`, XRL request 0x1300, needed right after
the logon; commit c99de28). Not yet tried by a real console.

## Tests

```sh
go test ./...                                   # DER, RC4-HMAC, store, and a full synthetic MACS -> XEAS -> TGS exchange
X360_KDC_TESTKEYS=private notes go test ./...   # plus replay of the live captures in private notes
go vet ./... && gofmt -l .
```

The synthetic test generates its own CA, XMACS and console keys, builds the three requests the way the
firmware does and decodes the replies the way XAM's parser does (nonce echo, key sizes, 108 -> 84 and
208 -> 184 records, ticket <= 1024 bytes), then checks every rejection: each tampered byte region of the
console block, another CA, wrong cname, tampered CE/timestamp/authenticator/D6, modified request body, foreign
or expired ticket, stale authenticator, user ids present, missing provenance. The replay test works on a copy
of the account store and sets the clock to each capture's time, so the saved datagrams validate; on this
workstation run tests with `TMPDIR=private notes` (never /tmp).

## Assumed, not established

**Guessed (not established by the notes).** 0x645 always answers exists: the core client has no lookup by email
and a constant avoids an enumeration oracle (a wrong email fails at 0x608). The 20 trailing bytes of 0x64A are
SHA-1 of the modulus. The online XUID takes 40 low bits. The fallback gamertag from the email. Without the gateway
header the console is the 12 low decimal digits of the machine id. `X-X360-Account` is trusted as sent by the
gateway: Traefik also exposes `/xuacs` on port 80, so a direct caller could set it; the password is still
required, but restrict the route if that matters. The domain/realm strings follow the task (`xbox.com`/`XBOX.COM`;
the notes also mention `PASSPORT.NET`). Error replies are plain HTTP statuses; how the applet maps them to the
messages (the `0x80152016`-style codes) is unknown. The 0x649 body layout is unparsed.

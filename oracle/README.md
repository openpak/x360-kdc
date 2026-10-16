# Python protocol oracle (reference only)

The scripts in this directory are the throwaway Python stand-ins that were used to derive the
Xbox 360 Live protocol from the firmware before the Go services existed. They are kept as the
reference the Go code was ported from and for comparing captures; they are not deployed and not
maintained as a service.

- `kdc.py`: MACS AS-REQ/AS-REP (DER helpers, RC4-HMAC, OAEP, console CA and signature checks).
- `xeas.py`: XEAS account authentication on top of `kdc.py`.
- `xetgs.py`: XETGS sg/S0 ticket-granting (entry point for all three on UDP 18088).
- `sg.py`: security gateway on UDP 3074 (initiation, key schedule, 0x5887 record, data packets)
  plus the XEXDS probe reply from `udpcap.py`.
- `sg_data_check.py`: data-packet seal/open against a saved session.
- `check_*.py`: offline checks against saved captures.

Run from a directory holding `../keys` (dev key material, never committed) and `../run/logs`
captures, with plain `python3` (the scripts validate with assertions).

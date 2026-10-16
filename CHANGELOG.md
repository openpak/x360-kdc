# Changelog: x360-kdc

## Unreleased

- 2026-10-16: first cut. Go port of OpenPak's Python oracle for the Xbox 360 Kerberos stages on UDP 88:
  MACS console authentication (OAEP secret, CA PSS and console PKCS#1 signatures, CE HMAC, encrypted
  timestamp; account record in padata 0xCB), XEAS machine-account exchange (stored account with
  provenance, CE, 5-minute timestamp; authenticated TGT) and the XETGS `sg/S0` TGS-REQ (own-ticket check,
  authenticator with body MD5, D6 under D(session, nonce); D7 service record with services 1 and 20 at a
  configurable SG address). JSON account store (0600, atomic) and 16-byte ticket key file. Unit tests, a
  synthetic end-to-end exchange with every rejection path, and replay of the live captures with the dev
  keys. Not deployed, no tag, not yet tried by the emulator itself.

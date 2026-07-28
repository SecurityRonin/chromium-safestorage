# 0002 — audited RustCrypto only; refuse, never fabricate

- Status: accepted
- Date: 2026-07-29

## Context

This crate produces a *value* (an AES key, a decrypted cookie) that an
independent oracle can check. That is exactly the zone where a hand-rolled or
placeholder crypto primitive is most dangerous: a "simplified" AES or a stubbed
PBKDF2 returns plausible-but-wrong bytes, passes a length-only test, and — in a
forensic tool — fabricates evidence.

## Decision

- Every primitive comes from an **audited RustCrypto crate**: `pbkdf2` + `sha1`
  (PBKDF2-HMAC-SHA1 derivation), `aes` + `cbc` + `cipher` (AES-128-CBC with the
  fixed 16-space IV and PKCS#7), `sha2` (the domain-hash verification), and the
  AES-256-GCM path is delegated to `dpapi-core` (`aes-gcm`). No primitive is
  hand-rolled.
- **No placeholder ever returns bytes.** A locked keychain → `KeychainLocked`; an
  absent/wrong DPAPI master key → `Dpapi(_)`; a wrong AES-128 key → `BadPadding`
  (PKCS#7 fails); a wrong/forged AES-256-GCM blob → `GcmDecryptFailed`. All are
  loud typed errors with a non-zero CLI exit.
- Unknown cookie prefixes surface the **actual leading bytes** (hex), never a bare
  "unrecognised".

## Consequences

- Correctness is validated against independent oracles (ADR-referenced
  `docs/validation.md`): an Apple-minted keychain, Python-`cryptography` cookie
  ciphertexts, RFC 6070 PBKDF2 vectors, the published Linux `v10` key, and a live
  real-Chrome loop — not a self-authored round-trip (which would be circular).
- The crate is fuzzed (cookie + `Local State` targets); the invariant is "no input
  panics", backing the panic-free lint posture.

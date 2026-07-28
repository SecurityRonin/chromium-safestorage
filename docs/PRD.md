# PRD — chromium-safestorage

*Product tier: it ships a runnable binary (`safestore4n6`) an examiner uses, and
a library others link. Both PRD and ADRs apply.*

## Problem

Chrome, Edge, and Brave encrypt cookies, saved logins, and (increasingly)
messenger databases with a single per-user AES key — the "Safe Storage" key.
Recovering that one key turns an acquired browser profile from opaque blobs into
readable evidence. But the key lives in a different place, protected a different
way, on each OS:

- **macOS** — a `<App> Safe Storage` generic-password in the login Keychain.
- **Windows** — a DPAPI-wrapped `os_crypt.encrypted_key` inside `Local State`.
- **Linux** — a gnome-keyring / kwallet secret (`v11`) or a hard-coded passphrase (`v10`).

DFIR tooling that hard-codes one OS, or that re-implements the crypto by hand,
either misses cases or (worse) ships a placeholder that returns plausible-but-
wrong bytes. This DLEAPP-phase-2 component gives the fleet a single, audited,
OS-dispatched recovery path.

## Users & use cases

- **Forensic examiners** recovering Chromium secrets from an acquired disk
  (macOS keychain, Windows `Local State`, Linux profile) — via `safestore4n6` or
  the orchestration layer.
- **Fleet libraries** (browser-forensic, issen) that hold cookie `encrypted_value`
  bytes and need the key to decrypt them — via `chromium-safestorage-core`.

## Scope

- Recover the Safe Storage key on macOS, Windows, and Linux (`v10`/`v11`).
- Decrypt a Chromium `Cookies` DB `encrypted_value` (`v10`/`v11` CBC, `v10`/`v20`
  GCM), with verified 32-byte domain-hash stripping.
- A `safestore4n6` CLI (text + JSON) with per-OS subcommands.

## Non-goals

- Reading the cookie/login SQLite databases themselves (that is browser-forensic's
  job — this crate takes raw `encrypted_value` bytes).
- Live extraction of the macOS keychain secret through the OS Keychain service, or
  live DPAPI via `CryptUnprotectData` — recovery is **offline** and medium-agnostic
  (the OS-native live paths belong to the acquiring tool). The analyst supplies the
  login password / DPAPI master key.
- App-Bound Encryption (Chrome 127+ Windows `v20` elevation-service key wrapping)
  beyond decrypting a `v20` GCM value given the AES-256 key.

## Success criteria

- Correctness proven against **independent oracles** (Apple-minted keychain,
  Python-`cryptography` cookie ciphertexts, RFC 6070 PBKDF2, published Linux key,
  and a live real-Chrome loop) — see `docs/validation.md`.
- Panic-free on arbitrary input (fuzzed); a wrong/absent key is a loud error.
- `#![forbid(unsafe_code)]`; audited RustCrypto only.

# chromium-safestorage

[![Crates.io core](https://img.shields.io/crates/v/chromium-safestorage-core.svg?label=core)](https://crates.io/crates/chromium-safestorage-core)
[![Crates.io forensic](https://img.shields.io/crates/v/chromium-safestorage-forensic.svg?label=forensic)](https://crates.io/crates/chromium-safestorage-forensic)
[![Docs.rs](https://img.shields.io/docsrs/chromium-safestorage-core?label=docs.rs)](https://docs.rs/chromium-safestorage-core)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/chromium-safestorage/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/chromium-safestorage/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security advisories](https://img.shields.io/badge/cargo--deny-clean-success.svg)](deny.toml)

**Recover the Chromium 'Safe Storage' key — the one key that unlocks every Chrome / Edge / Brave cookie, saved login, and messenger database — from an acquired disk, dispatched by source OS.**

One key protects them all. On macOS it lives in the login Keychain; on Windows it is DPAPI-wrapped inside `Local State`; on Linux it comes from the keyring (`v11`) or a hard-coded passphrase (`v10`). `chromium-safestorage` recovers it on all three and hands you a `RecoveredKey` that decrypts a `v10` cookie value straight from the `Cookies` DB — with **audited RustCrypto only**, and a **loud error, never a fabricated key**, when the input can't be unlocked.

```rust
use chromium_safestorage_core::{recover_key, KeySource};

// macOS: read `Chrome Safe Storage` from an acquired login.keychain-db …
let keychain = std::fs::read("login.keychain-db")?;
let key = recover_key(KeySource::MacOs {
    keychain: &keychain,
    login_password: b"login-password",
    service: "Chrome Safe Storage",
})?;

// … then decrypt a v10 cookie value straight from the Cookies DB.
let plaintext = key.decrypt_cookie(encrypted_value)?;
# Ok::<(), chromium_safestorage_core::SafeStorageError>(())
```

## What it recovers

| OS | Key source | Derivation | Cipher | Key |
|---|---|---|---|---|
| **macOS** | `<App> Safe Storage` Keychain generic-password (offline via [`keychain-core`]) | PBKDF2-HMAC-SHA1, salt `saltysalt`, 1003 rounds | AES-128-CBC | 16 B |
| **Windows** | `Local State` `os_crypt.encrypted_key`, DPAPI-unwrapped (via [`dpapi-core`]) | DPAPI | AES-256-GCM (`v10`) | 32 B |
| **Linux `v11`** | gnome-keyring / kwallet Secret Service secret | PBKDF2-HMAC-SHA1, 1 round | AES-128-CBC | 16 B |
| **Linux `v10`** | hard-coded `peanuts` passphrase (no secret needed) | PBKDF2-HMAC-SHA1, 1 round | AES-128-CBC | 16 B |

The recovered [`RecoveredKey`] is tagged with its cipher family, so `decrypt_cookie` picks AES-128-CBC or AES-256-GCM for you — you cannot apply the wrong one. Newer Chromium prepends a 32-byte `SHA-256(host_key)` domain hash to the plaintext; `strip_domain_hash` removes it **after verifying** it against the cookie's host.

## CLI — `safestore4n6`

```console
$ safestore4n6 macos --keychain login.keychain-db --password 'hunter2' \
      --service 'Chrome Safe Storage' --cookie cookie.bin --host accounts.google.com
[macos] key=cf5505107fba7a67db54d90d9137187b
cookie=SID=...

$ safestore4n6 windows --local-state 'Local State' --master-key 0x9828… --cookie cookie.bin
$ safestore4n6 linux-v10 --cookie cookie.bin --host example.com
```

A locked keychain or an absent DPAPI master key exits non-zero with a *present-but-locked* message — never a guessed key.

## Two crates

- **`chromium-safestorage-core`** — the OS-dispatch recovery + cookie decryption library (`recover_key`, `RecoveredKey`, `derive_*`). Import as `chromium_safestorage_core`.
- **`chromium-safestorage-forensic`** — the `safestore4n6` CLI on top.

## Trust, but verify

- **Fuzzed** — libFuzzer targets drive the cookie-decrypt and `Local State` edges over arbitrary bytes; the invariant is that no input panics.
- **Panic-free by lint** — `#![forbid(unsafe_code)]`, `clippy::unwrap_used` / `expect_used` denied in production; a wrong key, bad padding, or failed GCM tag is a typed `SafeStorageError`.
- **Audited crypto, no fabrication** — PBKDF2 / AES-CBC / AES-GCM come from the RustCrypto crates and the two fleet readers; no primitive is hand-rolled and no placeholder ever returns plausible-but-wrong bytes.
- **Validated against independent oracles** — see [`docs/validation.md`](docs/validation.md): an Apple-minted keychain fixture, Chromium `v10` cookie ciphertexts authored by Python's `cryptography` library, RFC 6070 PBKDF2 vectors, and the published Linux `v10` key — plus a live closed-loop test against real Chrome on macOS.

## Reference

Chromium `components/os_crypt/sync/os_crypt_mac.mm` / `os_crypt_linux.cc` / `os_crypt_win.cc` (`kSalt = "saltysalt"`, macOS `kDerivedKeyIterations = 1003`, Linux fallback password `"peanuts"`, `v10`/`v11`/`v20` prefixes).

[`keychain-core`]: https://github.com/SecurityRonin/keychain-forensic
[`dpapi-core`]: https://github.com/SecurityRonin/dpapi-forensic
[`RecoveredKey`]: https://docs.rs/chromium-safestorage-core
[`strip_domain_hash`]: https://docs.rs/chromium-safestorage-core

---

[Privacy Policy](https://securityronin.github.io/chromium-safestorage/privacy/) · [Terms of Service](https://securityronin.github.io/chromium-safestorage/terms/) · © 2026 Security Ronin Ltd

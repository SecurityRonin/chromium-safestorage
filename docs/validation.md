# Validation

`chromium-safestorage` produces values an independent oracle can check — an AES
key, a decrypted cookie — so every claim is validated against something this
crate did **not** author. A self-encoded round-trip would be circular (encoder
and decoder sharing the same bug ship green); the oracles below break that.

## Tier-2 — Apple-minted keychain (macOS path)

`core/tests/oracle_keychain.rs` opens `tests/data/css-test-login.keychain-db`, a
keychain **written by Apple's own `/usr/bin/security`** (see
[`tests/data/README.md`](https://github.com/SecurityRonin/chromium-safestorage/blob/main/tests/data/README.md)
for the exact minting commands and hashes). The test:

- recovers the `Chrome Safe Storage` secret via `recover_key(KeySource::MacOs{..})`
  and derives the AES-128 key `cf5505107fba7a67db54d90d9137187b`
  (`PBKDF2-HMAC-SHA1("SafeStorageDemoKey01","saltysalt",1003,16)`);
- recovers a second browser (`Brave Safe Storage`), proving the path is the general
  `<App> Safe Storage` rule, not a Chrome special case;
- asserts a wrong login password → `SafeStorageError::KeychainLocked`, never a
  fabricated key.

Apple wrote the salt, wrapped the DBKey, and encrypted the payloads through its
production code, so this is a genuine independent-oracle check.

## Tier-2 — Chromium `v10` cookie ciphertext (macOS/Linux CBC path)

`core/tests/oracle_cookie.rs` decrypts `v10` cookie blobs that were **encrypted by
Python's `cryptography` library** (a different AES-128-CBC + PBKDF2 implementation),
not by this crate. It asserts:

- the macOS key (from the keychain password, 1003 rounds) decrypts
  `v10 || AES-128-CBC(IV=16×0x20, PKCS#7("chromium-safe-storage-demo-cookie"))`
  to the exact plaintext;
- the modern layout `v10 || CBC(SHA-256("example.com") || "cookie-value-42")`
  decrypts, and `strip_domain_hash(pt, b"example.com")` verifies-and-removes the
  32-byte prefix to yield `cookie-value-42` — while a wrong host leaves the bytes
  intact;
- the Linux `v10` (`peanuts`, 1 round) key decrypts a Linux-authored blob;
- a wrong key fails PKCS#7 → `SafeStorageError::BadPadding` (no fabricated
  plaintext).

## Tier-2 — Windows `Local State` + `v10` GCM (Windows path)

The same test drives `dpapi-core`'s impacket-validated tier-1 vectors through this
crate's `recover_key(KeySource::Windows{..})` and
`RecoveredKey::decrypt_cookie`: the DPAPI-wrapped `os_crypt.encrypted_key`
recovers the 32-byte AES-256 key, which then AES-256-GCM-decrypts a `v10` cookie
to `forensic-session-token-42` (impacket authored both the blob and the answer —
an independent oracle). An all-zero master key → `SafeStorageError::Dpapi(_)`.

## Tier-1 — KDF known-answer tests

`derive_key` is pinned at the primitive level:

- **RFC 6070** PBKDF2-HMAC-SHA1 vector (`"password"`,`"salt"`,c=1,dkLen=20 →
  `0c60c80f961f0e71f3a9b524af6012062fe037a6`), truncated to the 16-byte key length;
- the **published Linux `v10` key** `fd621fe5a2b402539dfa147ca9272778`
  (`PBKDF2("peanuts","saltysalt",1,16)`), cross-checked against many independent
  public write-ups.

## Tier-2 — live closed loop against real Chrome (this host, env-gated)

`core/tests/live_chrome.rs` (run with `CHROMIUM_SAFESTORAGE_LIVE=1`) closes the
full real-world loop on a macOS host with Chrome installed:

1. read the real `<App> Safe Storage` password from the login Keychain
   (`security find-generic-password`, supplied to the test via env — never printed);
2. `derive_macos_key` → the real AES-128 key;
3. read a real `v10` `encrypted_value` from `~/Library/Application Support/…/Cookies`;
4. `RecoveredKey::decrypt_cookie` → a well-formed plaintext (valid after
   PKCS#7/`strip_domain_hash`), asserting the padding check passes.

The test never prints the key or the secret. It is skipped cleanly when the env
var or the artifacts are absent, so CI (which has neither Chrome nor the Keychain)
stays green from committed bytes alone.

## Robustness

- `#![forbid(unsafe_code)]`; `clippy::unwrap_used` / `expect_used` denied in
  production. A wrong key, bad padding, or failed GCM tag is a typed
  `SafeStorageError`.
- `cargo-fuzz` targets (`fuzz_cookie`, `fuzz_local_state`) drive the cookie-decrypt
  and `Local State` extraction over arbitrary bytes; the invariant is that no input
  panics.

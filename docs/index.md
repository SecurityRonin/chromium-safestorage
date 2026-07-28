# chromium-safestorage

Recover the Chromium **Safe Storage** AES key — the key that encrypts Chrome /
Edge / Brave cookies, saved logins, and messenger databases — from acquired
artifacts, dispatched by source OS.

| OS | Key source | Cipher | Key |
|---|---|---|---|
| macOS | `<App> Safe Storage` Keychain generic-password → PBKDF2 (1003) | AES-128-CBC | 16 B |
| Windows | `Local State` `os_crypt.encrypted_key` → DPAPI | AES-256-GCM | 32 B |
| Linux `v11` | gnome-keyring / kwallet secret → PBKDF2 (1) | AES-128-CBC | 16 B |
| Linux `v10` | hard-coded `peanuts` → PBKDF2 (1) | AES-128-CBC | 16 B |

See the [README](https://github.com/SecurityRonin/chromium-safestorage#readme)
for usage, and [Validation](validation.md) for how correctness is proven against
independent oracles.

## Crates

- **`chromium-safestorage-core`** — the recovery + decryption library.
- **`chromium-safestorage-forensic`** — the `safestore4n6` CLI.

## Security

Audited RustCrypto only; `#![forbid(unsafe_code)]`; a wrong or missing key is a
loud typed error, never a fabricated key. See
[SECURITY.md](https://github.com/SecurityRonin/chromium-safestorage/blob/main/SECURITY.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd

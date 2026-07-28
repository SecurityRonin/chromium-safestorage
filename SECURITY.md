# Security Policy

`chromium-safestorage` recovers and uses the Chromium **Safe Storage** key that
encrypts Chrome/Edge/Brave cookies and logins. It parses **untrusted artifacts**
extracted from acquired or hostile systems — macOS keychains, Windows `Local
State` / DPAPI blobs, and Chromium `Cookies` databases. Hostile input is the
expected case, not an edge case.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`chromium-safestorage` repository](https://github.com/SecurityRonin/chromium-safestorage/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include the affected version and target triple, a minimal reproducing
input (keychain / `Local State` / cookie blob), and the observed vs. expected
behaviour.

## Security posture

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **Audited cryptography only** — key derivation (PBKDF2-HMAC-SHA1) and cookie
  decryption (AES-128-CBC, AES-256-GCM) use the RustCrypto crates (`pbkdf2`,
  `aes`, `cbc`, `aes-gcm`, `sha1`, `sha2`); no primitive is hand-rolled and no
  placeholder ever returns plausible-but-wrong bytes. A wrong or missing key is
  a typed error, never a fabricated key or cookie.
- **Refuse, don't fabricate** — a locked keychain, an absent DPAPI master key, or
  a failed AES tag surfaces as a loud typed error with a non-zero CLI exit.
- **No panics on malicious input** — `clippy::unwrap_used` / `expect_used` are
  denied in production; malformed input surfaces as an error, not a crash.

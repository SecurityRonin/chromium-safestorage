# 0001 — core/forensic split and OS-dispatched recovery

- Status: accepted
- Date: 2026-07-29

## Context

Chromium's Safe Storage key is recovered differently on each OS (macOS Keychain,
Windows DPAPI, Linux keyring/`peanuts`), but the *downstream* use is identical:
you get an AES key and decrypt cookie/login `encrypted_value` bytes. We need a
shape that (a) fits the fleet's reader/analyzer standard, and (b) makes the
per-OS branching a data decision, not scattered `cfg!` code.

## Decision

Two crates, matching the fleet Pattern-A split:

- **`chromium-safestorage-core`** — the recovery library. A single entry point
  `recover_key(KeySource) -> Result<RecoveredKey, _>` dispatches on a `KeySource`
  enum whose variants (`MacOs`, `Windows`, `LinuxV11`, `LinuxV10`) carry exactly
  the inputs that OS needs. Recovery is **offline and medium-agnostic** — it takes
  `&[u8]` and analyst-supplied secrets, so an examiner on any host can recover a
  key from an image of any OS. Platform is a *parameter*, not a compile target.
- **`chromium-safestorage-forensic`** — the `safestore4n6` CLI (per-OS
  subcommands) plus the Humble-Object shell.

`RecoveredKey` is a tagged enum (`Aes128Cbc` / `Aes256Gcm`) so `decrypt_cookie`
selects the cipher from the key family — a caller cannot apply CBC to a GCM blob
(secure by design). `Debug` redacts the key bytes.

## Consequences

- The macOS/Linux paths and the Windows path share one output type and one
  cookie-decrypt surface; adding a browser variant (`Brave`/`Edge Safe Storage`)
  is just a different `service` string, not new code.
- The library compiles and runs on every platform (both fleet readers are pure
  Rust), so CI tests every path on Linux/macOS/Windows runners.

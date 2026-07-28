# 0003 — reuse keychain-core and dpapi-core, don't re-implement

- Status: accepted
- Date: 2026-07-29

## Context

The macOS path needs to read a `<App> Safe Storage` generic-password out of a
`login.keychain-db`; the Windows path needs to DPAPI-unwrap
`os_crypt.encrypted_key` from `Local State`. Both are substantial format+crypto
problems the fleet already solves in dedicated crates.

## Decision

Depend on the fleet readers rather than re-parsing the formats here (fleet
"prefer our own crates" rule):

- **macOS** → `keychain-core` (`Keychain::open` → `unlock(login_password)` →
  `generic_secrets()`), then derive the AES-128 key locally.
- **Windows** → `dpapi-core` (`parse_local_state_encrypted_key` →
  `decrypt_local_state_key`) for the AES-256 key, and `detect_chrome_cookie_encoding`
  + `decrypt_v10_cookie` for the `v10`/`v20` GCM cookie path.

Both are **path dependencies** now (neither is published yet); dependents switch
to the registry version on publish, per the fleet dependency rule. Their errors
are mapped into this crate's `SafeStorageError` (`KeychainLocked` / `Dpapi(_)`) so
the refuse-don't-fabricate boundary is preserved end to end.

## Consequences

- This crate owns only the *Safe Storage specific* knowledge: the PBKDF2 salt /
  iteration counts, the `saltysalt` / `peanuts` / `v10`/`v11`/`v20` constants, the
  AES-128-CBC cookie format, and the OS dispatch. The heavy format parsing lives
  where it belongs.
- The AES-256-GCM cookie code is not duplicated — it reuses `dpapi-core`'s vetted,
  fuzzed implementation.

# Test data — provenance

All fixtures here are small, clearly-owned, and committed. See the fleet catalog
`ronin-issen/docs/test-data-catalog.md` for the cross-repo index.

Straight ASCII is used in paths/commands.

## css-test-login.keychain-db  — REAL-self (OS-minted, independent oracle)

- **Source**: minted on a macOS host with Apple's own `/usr/bin/security` tool —
  Apple's production CDSA/keychain code wrote the PBKDF2 salt, derived and
  3DES-wrapped the DBKey, and encrypted the SSGP payloads. None of it was authored
  by this crate, so recovering the known secrets from it is an **independent-oracle
  (tier-2)** check, not a self-consistent round-trip.
- **MD5**: `1e6f1a007edf032e30086dc44737127e`
- **SHA-256**: `9d616654f414033a69ba57e9789b0500ab2287ef32f81918953659db3509461d`
- **Generator command** (verbatim):
  ```sh
  KC=/tmp/css-test-login.keychain-db
  security create-keychain -p "TestPass123!" "$KC"
  security set-keychain-settings "$KC"
  security unlock-keychain  -p "TestPass123!" "$KC"
  security add-generic-password -a "Chrome" -s "Chrome Safe Storage" -w "SafeStorageDemoKey01" "$KC"
  security add-generic-password -a "Brave"  -s "Brave Safe Storage"  -w "BraveDemoStorageKey9" "$KC"
  security add-generic-password -a "alice"  -s "MyLoginService"      -w "not-a-safe-storage-pw" "$KC"
  ```
- **Ground truth** (fixed by the command above):
  - login password: `TestPass123!`
  - `Chrome` / `Chrome Safe Storage` → `SafeStorageDemoKey01`
    → macOS AES-128 key `PBKDF2-HMAC-SHA1("SafeStorageDemoKey01","saltysalt",1003,16)`
      = `cf5505107fba7a67db54d90d9137187b`
  - `Brave`  / `Brave Safe Storage`  → `BraveDemoStorageKey9`
- **Used by**: `core/tests/oracle_keychain.rs`.
- **Redistribution**: contains only demo passwords we chose; safe to commit.

## v10 cookie ciphertext vectors  — REAL-ext oracle (Python `cryptography`)

Not committed as files; the hex constants live inline in
`core/tests/oracle_cookie.rs`. They were produced by **Python's `cryptography`
library (v48.0.0)** — an independent AES-128-CBC + PBKDF2 implementation — so that
this crate's decrypt is checked against a different implementation, not itself.

Generator (verbatim):
```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def derive(pw, iters): return hashlib.pbkdf2_hmac('sha1', pw, b'saltysalt', iters, 16)
def enc_v10(key, pt):
    iv = b' '*16
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad])*pad
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return b'v10' + c.update(pt) + c.finalize()

# macOS, password matches the keychain fixture (1003 rounds):
enc_v10(derive(b'SafeStorageDemoKey01', 1003), b'chromium-safe-storage-demo-cookie')
# modern (32-byte SHA256(host) domain-hash prefix + value), host=b"example.com":
enc_v10(derive(b'SafeStorageDemoKey01', 1003), hashlib.sha256(b'example.com').digest() + b'cookie-value-42')
# Linux v10 (peanuts, 1 round):
enc_v10(derive(b'peanuts', 1), b'linux-peanuts-cookie')
```

## Windows DPAPI vectors  — REAL-ext oracle (impacket, via dpapi-core)

The Windows `Local State` + `v10` GCM path reuses `dpapi-core`'s impacket-validated
tier-1 vectors (see that crate's `tests/data/README.md`). `core/tests/oracle_cookie.rs`
drives them through this crate's `recover_key` / `RecoveredKey::decrypt_cookie`.

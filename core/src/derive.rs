//! Key derivation for the Chromium 'Safe Storage' AES key.
//!
//! On macOS and Linux, Chromium derives the cookie/login AES-128 key from a
//! passphrase with **PBKDF2-HMAC-SHA1**, a fixed salt `saltysalt`, and a
//! platform-specific iteration count:
//!
//! | Platform | Passphrase source | Iterations | Key |
//! |---|---|---|---|
//! | macOS | Keychain `<App> Safe Storage` generic-password | 1003 | AES-128 |
//! | Linux `v11` | Secret Service (gnome-keyring / kwallet) | 1 | AES-128 |
//! | Linux `v10` | hard-coded `peanuts` | 1 | AES-128 |
//!
//! (Windows uses AES-256 with a DPAPI-wrapped key — see [`crate::recover`].)
//!
//! All derivation uses the audited RustCrypto `pbkdf2` + `sha1` crates; nothing
//! is hand-rolled.
//!
//! Reference: Chromium `components/os_crypt/sync/os_crypt_mac.mm` and
//! `os_crypt_linux.cc` (`kSalt = "saltysalt"`, `kEncryptionVersionPrefix = "v10"`,
//! macOS `kDerivedKeyIterations = 1003`, Linux `1`, Linux fallback password
//! `"peanuts"`).

/// The fixed PBKDF2 salt Chromium uses on every non-Windows platform.
pub const SALT: &[u8] = b"saltysalt";

/// PBKDF2 iteration count on macOS.
pub const MACOS_ITERATIONS: u32 = 1003;

/// PBKDF2 iteration count on Linux (both `v10` and `v11`).
pub const LINUX_ITERATIONS: u32 = 1;

/// The hard-coded Linux `v10` passphrase (used when no keyring secret exists).
pub const LINUX_V10_PASSWORD: &[u8] = b"peanuts";

/// The derived Safe Storage key length on macOS / Linux (AES-128).
pub const KEY_LEN: usize = 16;

/// Derive a 16-byte AES-128 key with `PBKDF2-HMAC-SHA1(password, "saltysalt",
/// iterations)`.
///
/// This is the single primitive behind every macOS/Linux path; callers pick the
/// iteration count via [`derive_macos_key`] / [`derive_linux_v11_key`] /
/// [`linux_v10_key`].
#[must_use]
pub fn derive_key(password: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, SALT, iterations, &mut key);
    key
}

/// Derive the macOS Safe Storage key from the Keychain passphrase (1003 rounds).
#[must_use]
pub fn derive_macos_key(safe_storage_password: &[u8]) -> [u8; KEY_LEN] {
    derive_key(safe_storage_password, MACOS_ITERATIONS)
}

/// Derive the Linux `v11` key from the Secret Service (keyring) passphrase (1 round).
#[must_use]
pub fn derive_linux_v11_key(keyring_secret: &[u8]) -> [u8; KEY_LEN] {
    derive_key(keyring_secret, LINUX_ITERATIONS)
}

/// Derive the Linux `v10` key — the hard-coded `peanuts` passphrase, 1 round.
#[must_use]
pub fn linux_v10_key() -> [u8; KEY_LEN] {
    derive_key(LINUX_V10_PASSWORD, LINUX_ITERATIONS)
}

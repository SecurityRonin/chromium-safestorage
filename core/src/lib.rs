//! Recover the Chromium **Safe Storage** AES key — the key that encrypts
//! Chrome / Edge / Brave cookies, saved logins, and messenger databases — from
//! acquired artifacts, dispatched by source OS.
//!
//! | OS | Key source | Cipher | Key |
//! |---|---|---|---|
//! | macOS | `<App> Safe Storage` Keychain generic-password → PBKDF2 (1003) | AES-128-CBC | 16 B |
//! | Windows | `Local State` `os_crypt.encrypted_key` → DPAPI | AES-256-GCM | 32 B |
//! | Linux `v11` | gnome-keyring / kwallet secret → PBKDF2 (1) | AES-128-CBC | 16 B |
//! | Linux `v10` | hard-coded `peanuts` → PBKDF2 (1) | AES-128-CBC | 16 B |
//!
//! ```no_run
//! use chromium_safestorage_core::{recover_key, KeySource};
//! let keychain = std::fs::read("login.keychain-db")?;
//! let key = recover_key(KeySource::MacOs {
//!     keychain: &keychain,
//!     login_password: b"login-password",
//!     service: "Chrome Safe Storage",
//! })?;
//! // Then decrypt a v10 cookie value straight from the Cookies DB:
//! let plaintext = key.decrypt_cookie(cookie_encrypted_value)?;
//! # Ok::<(), chromium_safestorage_core::SafeStorageError>(())
//! ```
//!
//! **Audited crypto only.** Derivation (PBKDF2-HMAC-SHA1) and decryption
//! (AES-128-CBC, AES-256-GCM) go through the RustCrypto crates and the two fleet
//! readers (`keychain-core`, `dpapi-core`). No primitive is hand-rolled and no
//! placeholder ever returns plausible-but-wrong bytes: a wrong or missing key is
//! a typed [`SafeStorageError`], never a fabricated key or cookie.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cookie;
pub mod derive;
pub mod error;
pub mod recover;

pub use cookie::{strip_domain_hash, RecoveredKey};
pub use derive::{
    derive_key, derive_linux_v11_key, derive_macos_key, linux_v10_key, KEY_LEN, LINUX_ITERATIONS,
    LINUX_V10_PASSWORD, MACOS_ITERATIONS, SALT,
};
pub use error::SafeStorageError;
pub use recover::{extract_encrypted_key, recover_key, KeySource};

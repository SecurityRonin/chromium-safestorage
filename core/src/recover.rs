//! OS-dispatched recovery of the Chromium 'Safe Storage' key.
//!
//! One entry point, [`recover_key`], takes a [`KeySource`] that names the source
//! OS and its inputs, and returns a [`RecoveredKey`] tagged with the right cipher
//! family. The three OS paths:
//!
//! - **macOS** — read the `<App> Safe Storage` generic-password from a
//!   `login.keychain-db` (offline, via `keychain-core`), then derive the AES-128
//!   key (PBKDF2-HMAC-SHA1, 1003 rounds).
//! - **Windows** — pull `os_crypt.encrypted_key` from `Local State`, DPAPI-decrypt
//!   it (via `dpapi-core`) to the 32-byte AES-256 key (`v10`).
//! - **Linux** — `v11` derives from a keyring secret; `v10` uses the hard-coded
//!   `peanuts` passphrase and needs no secret at all.
//!
//! A wrong or absent secret/master key is always a loud error — never a
//! fabricated key.

use crate::cookie::RecoveredKey;
use crate::error::SafeStorageError;

/// The source OS and inputs for a recovery, dispatched by [`recover_key`].
#[derive(Debug)]
#[non_exhaustive]
pub enum KeySource<'a> {
    /// macOS: offline keychain read + PBKDF2 derivation.
    MacOs {
        /// Raw bytes of the `login.keychain-db` file.
        keychain: &'a [u8],
        /// The account login password that unlocks the keychain.
        login_password: &'a [u8],
        /// The generic-password service to read, e.g. `Chrome Safe Storage`.
        service: &'a str,
    },
    /// Windows: DPAPI-unwrap the `Local State` cookie key.
    Windows {
        /// Raw bytes of the browser `Local State` JSON file.
        local_state_json: &'a [u8],
        /// The 64-byte DPAPI user master key (offline recovery input).
        dpapi_master_key: &'a [u8],
    },
    /// Linux `v11`: derive from the Secret Service (gnome-keyring / kwallet) secret.
    LinuxV11 {
        /// The `<App> Safe Storage` secret read from the keyring.
        keyring_secret: &'a [u8],
    },
    /// Linux `v10`: the hard-coded `peanuts` passphrase (no external secret).
    LinuxV10,
}

/// Recover the Safe Storage key for the given source.
pub fn recover_key(_source: KeySource<'_>) -> Result<RecoveredKey, SafeStorageError> {
    unimplemented!("recover_key")
}

/// Extract the base64 `os_crypt.encrypted_key` string from a `Local State` JSON
/// document (the Windows master-key location). Returns the raw base64 bytes.
pub fn extract_encrypted_key(_local_state_json: &[u8]) -> Result<Vec<u8>, SafeStorageError> {
    unimplemented!("extract_encrypted_key")
}

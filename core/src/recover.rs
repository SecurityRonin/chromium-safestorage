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

use keychain_core::{Keychain, KeychainError};

use crate::cookie::RecoveredKey;
use crate::derive::{derive_linux_v11_key, derive_macos_key, linux_v10_key};
use crate::error::SafeStorageError;

/// The source OS and inputs for a recovery, dispatched by [`recover_key`].
///
/// Holds only borrowed inputs, so it is `Copy` — build it inline at the call.
#[derive(Debug, Clone, Copy)]
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
pub fn recover_key(source: KeySource<'_>) -> Result<RecoveredKey, SafeStorageError> {
    match source {
        KeySource::MacOs {
            keychain,
            login_password,
            service,
        } => recover_macos(keychain, login_password, service),
        KeySource::Windows {
            local_state_json,
            dpapi_master_key,
        } => recover_windows(local_state_json, dpapi_master_key),
        KeySource::LinuxV11 { keyring_secret } => Ok(RecoveredKey::Aes128Cbc(
            derive_linux_v11_key(keyring_secret),
        )),
        KeySource::LinuxV10 => Ok(RecoveredKey::Aes128Cbc(linux_v10_key())),
    }
}

/// macOS: read the `<App> Safe Storage` generic-password offline via
/// `keychain-core`, then derive the AES-128 key. A wrong login password is
/// reported [`SafeStorageError::KeychainLocked`] — never a fabricated key.
fn recover_macos(
    keychain: &[u8],
    login_password: &[u8],
    service: &str,
) -> Result<RecoveredKey, SafeStorageError> {
    let kc = Keychain::open(keychain).map_err(|e| SafeStorageError::Keychain(e.to_string()))?;
    let unlocked = kc.unlock(login_password).map_err(|e| match e {
        KeychainError::Locked => SafeStorageError::KeychainLocked,
        other => SafeStorageError::Keychain(other.to_string()),
    })?;

    let secret = unlocked
        .generic_secrets()
        .into_iter()
        .find(|s| s.service == service)
        .ok_or_else(|| SafeStorageError::ServiceNotFound(service.to_string()))?;

    Ok(RecoveredKey::Aes128Cbc(derive_macos_key(&secret.secret)))
}

/// Windows: DPAPI-unwrap `os_crypt.encrypted_key` from `Local State` via
/// `dpapi-core`, yielding the 32-byte AES-256 key. A wrong/absent master key
/// surfaces as [`SafeStorageError::Dpapi`] — never a fabricated key.
fn recover_windows(
    local_state_json: &[u8],
    dpapi_master_key: &[u8],
) -> Result<RecoveredKey, SafeStorageError> {
    let encrypted_key_b64 = extract_encrypted_key(local_state_json)?;
    let blob = dpapi_core::parse_local_state_encrypted_key(&encrypted_key_b64)
        .map_err(|e| SafeStorageError::Dpapi(e.to_string()))?;
    let key = dpapi_core::decrypt_local_state_key(&blob, dpapi_master_key)
        .map_err(|e| SafeStorageError::Dpapi(e.to_string()))?;
    Ok(RecoveredKey::Aes256Gcm(key))
}

/// Extract the base64 `os_crypt.encrypted_key` string from a `Local State` JSON
/// document (the Windows master-key location). Returns the raw base64 bytes.
pub fn extract_encrypted_key(local_state_json: &[u8]) -> Result<Vec<u8>, SafeStorageError> {
    let value: serde_json::Value =
        serde_json::from_slice(local_state_json).map_err(|_| SafeStorageError::NoEncryptedKey)?;
    value
        .get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(serde_json::Value::as_str)
        .map(|s| s.as_bytes().to_vec())
        .ok_or(SafeStorageError::NoEncryptedKey)
}

//! Tier-2 macOS validation against an Apple-minted keychain (`Doer-Checker`).
//!
//! `tests/data/css-test-login.keychain-db` was written by macOS's own `security`
//! tool (see `tests/data/README.md`) — Apple's production code authored the salt,
//! wrapped the `DBKey`, and encrypted the payloads. Recovering the known secret /
//! key from it proves this crate agrees with Apple, not with itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{recover_key, KeySource, RecoveredKey, SafeStorageError};

const KEYCHAIN: &[u8] = include_bytes!("../../tests/data/css-test-login.keychain-db");
const LOGIN_PASSWORD: &[u8] = b"TestPass123!";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn recovers_chrome_safe_storage_key() {
    let key = recover_key(KeySource::MacOs {
        keychain: KEYCHAIN,
        login_password: LOGIN_PASSWORD,
        service: "Chrome Safe Storage",
    })
    .expect("recover Chrome Safe Storage key");

    match key {
        RecoveredKey::Aes128Cbc(k) => {
            // PBKDF2("SafeStorageDemoKey01","saltysalt",1003,16).
            assert_eq!(k.to_vec(), hex("cf5505107fba7a67db54d90d9137187b"));
        }
        RecoveredKey::Aes256Gcm(_) => panic!("macOS must yield an AES-128-CBC key"),
    }
}

#[test]
fn recovers_a_second_browser_not_just_chrome() {
    // The path is the general `<App> Safe Storage` rule, not a Chrome special case.
    let key = recover_key(KeySource::MacOs {
        keychain: KEYCHAIN,
        login_password: LOGIN_PASSWORD,
        service: "Brave Safe Storage",
    })
    .expect("recover Brave Safe Storage key");
    assert_eq!(key.key_bytes().len(), 16);
}

#[test]
fn wrong_login_password_reports_locked_not_a_fabricated_key() {
    let err = recover_key(KeySource::MacOs {
        keychain: KEYCHAIN,
        login_password: b"wrong-password",
        service: "Chrome Safe Storage",
    })
    .expect_err("a wrong login password must not unlock");
    assert_eq!(err, SafeStorageError::KeychainLocked);
}

#[test]
fn missing_service_reports_not_found_with_the_name() {
    let err = recover_key(KeySource::MacOs {
        keychain: KEYCHAIN,
        login_password: LOGIN_PASSWORD,
        service: "Firefox Safe Storage",
    })
    .expect_err("no such service");
    match err {
        SafeStorageError::ServiceNotFound(svc) => assert_eq!(svc, "Firefox Safe Storage"),
        other => panic!("expected ServiceNotFound, got {other:?}"),
    }
}

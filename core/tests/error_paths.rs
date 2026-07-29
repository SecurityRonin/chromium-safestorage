//! Loud-failure and secure-output contracts of the core crate.
//!
//! These exercise the recovery/decryption *error* arms (a malformed keychain, a
//! malformed `Local State` key) and the two rendering contracts (a redacted
//! `Debug`, a human `Display` for every error variant). A wrong or corrupt input
//! must surface as a typed [`SafeStorageError`] carrying the offending detail —
//! never a fabricated key (see SECURITY.md / the crate docs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{recover_key, KeySource, RecoveredKey, SafeStorageError};

// --- recovery error arms (recover.rs) ---

#[test]
fn malformed_keychain_is_a_typed_error_showing_the_signature() {
    // A byte blob that is not a keychain must fail `Keychain::open`, surfacing the
    // reader's reason (the bad magic) — never a guessed key.
    let err = recover_key(KeySource::MacOs {
        keychain: b"not a keychain",
        login_password: b"TestPass123!",
        service: "Chrome Safe Storage",
    })
    .expect_err("garbage bytes are not a keychain");
    match err {
        SafeStorageError::Keychain(reason) => {
            // The diagnostic carries the offending signature (Show-the-bytes).
            assert!(
                reason.contains("signature"),
                "reason surfaces the bad magic: {reason}"
            );
        }
        other => panic!("expected Keychain(_), got {other:?}"),
    }
}

#[test]
fn malformed_local_state_encrypted_key_is_a_dpapi_error() {
    // `os_crypt.encrypted_key` present but not valid base64 → the DPAPI reader
    // rejects it; the failure is reported, not swallowed into a fabricated key.
    let json = br#"{"os_crypt":{"encrypted_key":"!!!not-base64!!!"}}"#;
    let err = recover_key(KeySource::Windows {
        local_state_json: json,
        dpapi_master_key: &[0u8; 64],
    })
    .expect_err("non-base64 encrypted_key");
    assert!(
        matches!(err, SafeStorageError::Dpapi(ref m) if m.contains("base64")),
        "expected a base64 DPAPI error, got {err:?}"
    );
}

// --- secure Debug: keys are never printed (cookie.rs) ---

#[test]
fn debug_never_leaks_key_material() {
    let cbc = RecoveredKey::Aes128Cbc([0xabu8; 16]);
    let gcm = RecoveredKey::Aes256Gcm([0xcdu8; 32]);
    let cbc_dbg = format!("{cbc:?}");
    let gcm_dbg = format!("{gcm:?}");
    assert!(cbc_dbg.contains("redacted"), "cbc debug redacts: {cbc_dbg}");
    assert!(gcm_dbg.contains("redacted"), "gcm debug redacts: {gcm_dbg}");
    // The raw key hex must not appear in the Debug output.
    assert!(!cbc_dbg.contains("abab"), "cbc key leaked: {cbc_dbg}");
    assert!(!gcm_dbg.contains("cdcd"), "gcm key leaked: {gcm_dbg}");
}

// --- human Display: every error variant renders a distinct, informative line ---

#[test]
fn every_error_variant_has_a_distinct_display() {
    let cases: &[(SafeStorageError, &str)] = &[
        (SafeStorageError::KeychainLocked, "LOCKED"),
        (SafeStorageError::Keychain("bad magic".into()), "bad magic"),
        (
            SafeStorageError::ServiceNotFound("Chrome Safe Storage".into()),
            "Chrome Safe Storage",
        ),
        (
            SafeStorageError::Dpapi("no master key".into()),
            "no master key",
        ),
        (SafeStorageError::NoEncryptedKey, "os_crypt.encrypted_key"),
        (SafeStorageError::CookieTooShort(2), "2 bytes"),
        (
            SafeStorageError::UnknownCookiePrefix("5a5a5a".into()),
            "5a5a5a",
        ),
        (SafeStorageError::BadPadding, "padding"),
        (SafeStorageError::GcmDecryptFailed, "GCM"),
    ];
    for (err, needle) in cases {
        let shown = err.to_string();
        assert!(
            shown.contains(needle),
            "Display of {err:?} should contain {needle:?}, got: {shown}"
        );
    }
}

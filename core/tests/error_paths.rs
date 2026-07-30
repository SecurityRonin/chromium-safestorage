//! Loud-failure and secure-output contracts of the core crate.
//!
//! These exercise the recovery/decryption *error* arms (a malformed keychain, a
//! malformed `Local State` key) and the two rendering contracts (a redacted
//! `Debug`, a human `Display` for every error variant). A wrong or corrupt input
//! must surface as a typed [`SafeStorageError`] carrying the offending detail —
//! never a fabricated key (see SECURITY.md / the crate docs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{
    recover_key, strip_domain_hash, KeySource, RecoveredKey, SafeStorageError,
};

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
fn a_keychain_that_opens_but_has_no_dbblob_reports_the_readers_reason() {
    // A keychain can be structurally valid enough to OPEN (correct `kych`
    // signature, parseable schema) and still fail to unlock for a reason that is
    // NOT a wrong password. Here the single schema table is not the METADATA
    // table, so there is no DbBlob to unwrap: the reader's own reason must be
    // surfaced verbatim instead of being flattened into "locked", which would
    // send an examiner hunting for a password that was never the problem.
    const HEADER_SIZE: usize = 20;
    const SCHEMA_HEADER_SIZE: usize = 8;
    const ATOM: usize = 4;
    let mut kc = vec![0u8; 96];
    let put =
        |b: &mut Vec<u8>, off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_be_bytes());
    put(&mut kc, 0, 0x6b79_6368); // 'kych'
    put(&mut kc, 12, HEADER_SIZE as u32); // schema follows the header
    put(&mut kc, HEADER_SIZE + ATOM, 1); // table_count
    put(&mut kc, HEADER_SIZE + SCHEMA_HEADER_SIZE, 12); // the one table's offset
    put(&mut kc, HEADER_SIZE + 12 + ATOM, 0x0000_0001); // NOT RECORD_METADATA

    let err = recover_key(KeySource::MacOs {
        keychain: &kc,
        login_password: b"TestPass123!",
        service: "Chrome Safe Storage",
    })
    .expect_err("a keychain with no metadata table cannot be unlocked");
    match err {
        SafeStorageError::Keychain(reason) => assert!(
            reason.contains("DbBlob"),
            "reason names the missing structure, not a wrong password: {reason}"
        ),
        other => panic!("expected Keychain(_) carrying the reader's reason, got {other:?}"),
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

// --- cookie prefix / envelope arms (cookie.rs) ---

#[test]
fn a_value_too_short_to_hold_a_prefix_is_reported_with_its_length() {
    // Anything under 3 bytes cannot even carry a `v10`/`v11` tag. The error names
    // the length it actually got, so an examiner can see the value was truncated
    // rather than mis-tagged.
    for value in [&b""[..], &b"v"[..], &b"v1"[..]] {
        let err = RecoveredKey::Aes128Cbc([0u8; 16])
            .decrypt_cookie(value)
            .expect_err("too short to be a cookie");
        assert_eq!(err, SafeStorageError::CookieTooShort(value.len()));
    }
}

#[test]
fn an_unrecognised_cbc_prefix_is_reported_with_its_leading_bytes() {
    // A prefix we do not know is not silently stripped or guessed at — the
    // diagnostic carries the offending bytes in hex (Show-the-unrecognized-value).
    let err = RecoveredKey::Aes128Cbc([0u8; 16])
        .decrypt_cookie(b"v99\x01\x02")
        .expect_err("v99 is not a Chromium cookie version");
    assert_eq!(
        err,
        SafeStorageError::UnknownCookiePrefix("76393901".to_owned())
    );
}

#[test]
fn a_v20_envelope_is_recognised_and_only_its_decryption_can_fail() {
    // Chromium 127+ writes `v20` app-bound cookies. The envelope must be parsed
    // like `v10` (same nonce||ciphertext||tag layout) — a wrong key then fails
    // GCM authentication, which is a decrypt failure, NOT an unknown prefix.
    let mut value = b"v20".to_vec();
    value.extend_from_slice(&[0u8; 12]); // nonce
    value.extend_from_slice(&[0xffu8; 32]); // ciphertext || tag
    let err = RecoveredKey::Aes256Gcm([0u8; 32])
        .decrypt_cookie(&value)
        .expect_err("random ciphertext cannot authenticate");
    assert_eq!(err, SafeStorageError::GcmDecryptFailed);
}

#[test]
fn a_non_gcm_envelope_is_reported_as_an_unknown_prefix() {
    // A value that is neither `v10` nor `v20` (here a bare DPAPI blob header) is
    // outside this path: report the leading bytes rather than attempting GCM on
    // an envelope whose nonce/ciphertext split is unknown.
    let mut value = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf".to_vec();
    value.extend_from_slice(&[0u8; 40]);
    let err = RecoveredKey::Aes256Gcm([0u8; 32])
        .decrypt_cookie(&value)
        .expect_err("a DPAPI blob is not a v10/v20 cookie");
    assert_eq!(
        err,
        SafeStorageError::UnknownCookiePrefix("01000000".to_owned())
    );
}

#[test]
fn an_unverified_domain_hash_prefix_is_left_in_place() {
    // The 32-byte prefix is stripped ONLY when it equals SHA256(host_key). With a
    // mismatch (older schema, or the wrong host supplied) the plaintext is
    // returned whole — dropping 32 bytes here would silently truncate a real
    // cookie value.
    let plaintext = [0xabu8; 40];
    assert_eq!(
        strip_domain_hash(&plaintext, b"example.com"),
        &plaintext[..],
        "a non-matching prefix is real data, not a domain hash"
    );
    // Shorter than the prefix: nothing to test against, so also unchanged.
    let short = [0xabu8; 8];
    assert_eq!(strip_domain_hash(&short, b"example.com"), &short[..]);
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

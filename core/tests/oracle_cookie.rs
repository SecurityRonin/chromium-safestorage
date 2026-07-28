//! Tier-2 cookie-decryption validation against independent oracles.
//!
//! CBC (`v10`) ciphertexts here were authored by Python's `cryptography` library;
//! the GCM (`v10`) Windows vectors come from `dpapi-core`'s impacket-validated set
//! (see `tests/data/README.md`). Neither was produced by this crate, so decrypting
//! them to the known plaintext is a real cross-implementation check, not a
//! self-consistent round-trip.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{
    derive_macos_key, recover_key, strip_domain_hash, KeySource, RecoveredKey, SafeStorageError,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- macOS / Linux CBC path (Python `cryptography` oracle) ---

// v10 || AES-128-CBC(IV=16*0x20, PKCS7("chromium-safe-storage-demo-cookie"))
// under key = PBKDF2("SafeStorageDemoKey01","saltysalt",1003,16).
const V10_MACOS_LEGACY: &str = "76313018b4b6b688fbe720da4ffdc408d035525b80dd7c7238689aff7c8491d0ccc3a4127901f54256f9b6414ca698617003ea";
const MACOS_LEGACY_PLAINTEXT: &[u8] = b"chromium-safe-storage-demo-cookie";

// Modern layout: v10 || CBC(SHA256("example.com") || "cookie-value-42").
const V10_MACOS_MODERN: &str = "7631304a055b8b38696dec32cbe71c54fc775d0959268338e40f8d08eb120b18107181daf882e96ad8acde13faec47faeebb14";
const MODERN_VALUE: &[u8] = b"cookie-value-42";

// Linux v10 (peanuts, 1 round) blob for "linux-peanuts-cookie".
const V10_LINUX: &str = "76313033a6267625d550af7cb215522eeb831a3e706cf653757174abb98f186c703181";
const LINUX_PLAINTEXT: &[u8] = b"linux-peanuts-cookie";

#[test]
fn macos_key_decrypts_python_authored_v10_cookie() {
    let key = RecoveredKey::Aes128Cbc(derive_macos_key(b"SafeStorageDemoKey01"));
    let pt = key.decrypt_cookie(&hex(V10_MACOS_LEGACY)).expect("decrypt");
    assert_eq!(pt, MACOS_LEGACY_PLAINTEXT);
}

#[test]
fn modern_cookie_domain_hash_is_verified_and_stripped() {
    let key = RecoveredKey::Aes128Cbc(derive_macos_key(b"SafeStorageDemoKey01"));
    let pt = key.decrypt_cookie(&hex(V10_MACOS_MODERN)).expect("decrypt");
    // Full plaintext is 32-byte SHA256(host) + value.
    assert_eq!(pt.len(), 32 + MODERN_VALUE.len());
    // Verified strip yields the real value …
    assert_eq!(strip_domain_hash(&pt, b"example.com"), MODERN_VALUE);
    // … but a wrong host must NOT cut 32 real bytes.
    assert_eq!(strip_domain_hash(&pt, b"wrong.example"), &pt[..]);
}

#[test]
fn linux_v10_peanuts_decrypts_without_a_secret() {
    let key = recover_key(KeySource::LinuxV10).expect("linux v10 key");
    let pt = key.decrypt_cookie(&hex(V10_LINUX)).expect("decrypt");
    assert_eq!(pt, LINUX_PLAINTEXT);
}

#[test]
fn linux_v11_derives_from_keyring_secret() {
    // v11 uses the keyring secret with 1 round; a blob encrypted under that key
    // round-trips. (Encoded here with the same peanuts value only to reuse a
    // vector; the point is the v11 dispatch derives with 1 round.)
    let key = recover_key(KeySource::LinuxV11 {
        keyring_secret: b"peanuts",
    })
    .expect("linux v11 key");
    let pt = key.decrypt_cookie(&hex(V10_LINUX)).expect("decrypt");
    assert_eq!(pt, LINUX_PLAINTEXT);
}

#[test]
fn wrong_key_fails_padding_not_a_fabricated_plaintext() {
    let key = RecoveredKey::Aes128Cbc([0u8; 16]);
    let err = key
        .decrypt_cookie(&hex(V10_MACOS_LEGACY))
        .expect_err("wrong key");
    assert_eq!(err, SafeStorageError::BadPadding);
}

#[test]
fn unknown_prefix_shows_the_bytes() {
    let key = RecoveredKey::Aes128Cbc(derive_macos_key(b"x"));
    let err = key
        .decrypt_cookie(b"ZZZsomethingelse")
        .expect_err("unknown prefix");
    match err {
        SafeStorageError::UnknownCookiePrefix(bytes) => {
            assert!(bytes.contains("5a5a5a"), "leading bytes surfaced: {bytes}");
        }
        other => panic!("expected UnknownCookiePrefix, got {other:?}"),
    }
}

// --- Windows GCM path (dpapi-core impacket oracle) ---

const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
const ENCRYPTED_KEY_B64: &str = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAz8Z9e40C+SoouK05ivQzGAAAAAAIAAAAAABBmAAAAAQAAIAAAAAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/AAAAAA6AAAAAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAA+t/5261X1EPXoNd8+fv91ognzpGyym/1M78vdGfOMphl2Zzre4QfJx4U0fUIzjosQAAAAP5yd3Yln699MQCEn7TqSfxp/Ba+vR7Ji1pSJ7TPr7zimD/5Slev0vK6H5r6Mq46ohSMEPLzAWzKvD5xxvJt1sA=";
const V10_GCM_COOKIE: &str = "7631300102030405060708090a0b0c1b5af334ffe7a1fe676c5ab453c8848232ab94aa630c69bae71883958ba23e4dfe4cc5faff526ce54b";
const GCM_PLAINTEXT: &[u8] = b"forensic-session-token-42";

fn local_state_json(b64: &str) -> String {
    format!("{{\"os_crypt\":{{\"encrypted_key\":\"{b64}\"}}}}")
}

#[test]
fn windows_local_state_recovers_aes256_key_and_decrypts_v10_gcm() {
    let json = local_state_json(ENCRYPTED_KEY_B64);
    let key = recover_key(KeySource::Windows {
        local_state_json: json.as_bytes(),
        dpapi_master_key: &hex(MASTER_KEY_HEX),
    })
    .expect("recover windows key");

    match &key {
        RecoveredKey::Aes256Gcm(k) => assert_eq!(k.len(), 32),
        RecoveredKey::Aes128Cbc(_) => panic!("windows must yield an AES-256-GCM key"),
    }

    let pt = key
        .decrypt_cookie(&hex(V10_GCM_COOKIE))
        .expect("gcm decrypt");
    assert_eq!(pt, GCM_PLAINTEXT);
}

#[test]
fn windows_absent_master_key_refuses() {
    let json = local_state_json(ENCRYPTED_KEY_B64);
    let err = recover_key(KeySource::Windows {
        local_state_json: json.as_bytes(),
        dpapi_master_key: &[0u8; 64],
    })
    .expect_err("all-zero master key must fail");
    assert!(matches!(err, SafeStorageError::Dpapi(_)));
}

#[test]
fn windows_local_state_without_encrypted_key_errors() {
    let err = recover_key(KeySource::Windows {
        local_state_json: b"{\"os_crypt\":{}}",
        dpapi_master_key: &hex(MASTER_KEY_HEX),
    })
    .expect_err("no encrypted_key");
    assert_eq!(err, SafeStorageError::NoEncryptedKey);
}

#[test]
fn windows_wrong_key_family_gcm_tag_fails_on_garbage() {
    // A valid AES-256 key but a corrupt GCM blob must fail the tag, not fabricate.
    let key = RecoveredKey::Aes256Gcm([0x11u8; 32]);
    let err = key
        .decrypt_cookie(&hex(V10_GCM_COOKIE))
        .expect_err("tag must fail");
    assert_eq!(err, SafeStorageError::GcmDecryptFailed);
}

//! Tier-1 known-answer tests for the PBKDF2-HMAC-SHA1 key derivation.
//!
//! The vectors are authored by independent parties (RFC 6070; the widely
//! published Chromium Linux `v10` key), so agreement proves this crate's
//! derivation is correct, not merely self-consistent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{derive_key, derive_macos_key, linux_v10_key};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 6070 PBKDF2-HMAC-SHA1 vector: P="password", S="salt", c=1, dkLen=20.
/// The 16-byte Chromium key is the first 16 bytes of that output.
#[test]
fn rfc6070_c1_first_16_bytes() {
    let full = hex("0c60c80f961f0e71f3a9b524af6012062fe037a6");
    let got = derive_key(b"password", 1);
    assert_eq!(got.to_vec(), full[..16].to_vec());
}

/// The published Chromium Linux `v10` key: PBKDF2("peanuts","saltysalt",1,16).
/// This exact value appears in many independent public write-ups.
#[test]
fn linux_v10_published_key() {
    assert_eq!(
        linux_v10_key().to_vec(),
        hex("fd621fe5a2b402539dfa147ca9272778")
    );
}

/// macOS uses 1003 rounds; deriving from the keychain fixture's known password
/// yields the fixed AES-128 key used across the cookie oracle tests.
#[test]
fn macos_1003_rounds_known_key() {
    assert_eq!(
        derive_macos_key(b"SafeStorageDemoKey01").to_vec(),
        hex("cf5505107fba7a67db54d90d9137187b")
    );
}

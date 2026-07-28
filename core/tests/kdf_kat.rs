//! Tier-1/2 known-answer tests for the PBKDF2-HMAC-SHA1 key derivation over the
//! fixed Chromium salt `saltysalt`.
//!
//! The Linux `v10` key is authored/published by independent parties (it appears
//! in many public write-ups), so agreement proves this crate's derivation is
//! correct, not merely self-consistent. The macOS 1003-round vector is a cross-
//! implementation check (computed by Python's `hashlib.pbkdf2_hmac`) and is the
//! key the keychain/cookie oracles reuse.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_core::{derive_macos_key, linux_v10_key};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

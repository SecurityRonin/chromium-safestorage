#![no_main]
//! Fuzz cookie decryption over arbitrary bytes. Invariant: never panic.
//!
//! `decrypt_cookie` runs on attacker-controllable `encrypted_value` bytes for
//! both cipher families (AES-128-CBC with the space IV, AES-256-GCM via
//! dpapi-core), plus the verified domain-hash strip. A wrong key or malformed
//! blob must return a typed error, never crash.

use chromium_safestorage_core::{strip_domain_hash, RecoveredKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Derive both key families from a slice of the input so the key varies.
    let mut k16 = [0u8; 16];
    let mut k32 = [0u8; 32];
    for (i, b) in data.iter().take(16).enumerate() {
        k16[i] = *b;
    }
    for (i, b) in data.iter().take(32).enumerate() {
        k32[i] = *b;
    }

    let _ = RecoveredKey::Aes128Cbc(k16).decrypt_cookie(data);
    let _ = RecoveredKey::Aes256Gcm(k32).decrypt_cookie(data);

    // The domain-hash strip must never panic on arbitrary plaintext/host.
    let host = data.get(..4).unwrap_or(b"");
    let _ = strip_domain_hash(data, host);
});

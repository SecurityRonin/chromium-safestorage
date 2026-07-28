#![no_main]
//! Fuzz the Windows `Local State` extraction + full recovery over arbitrary
//! bytes. Invariant: never panic.
//!
//! `extract_encrypted_key` parses attacker-controllable JSON, and `recover_key`
//! drives it through dpapi-core's DPAPI unwrap. Malformed JSON / base64 / blobs
//! must return a typed error, never crash.

use chromium_safestorage_core::{extract_encrypted_key, recover_key, KeySource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_encrypted_key(data);

    // Split the input into (local_state_json, master_key) and drive recovery.
    let (json, key) = data.split_at(data.len() / 2);
    let _ = recover_key(KeySource::Windows {
        local_state_json: json,
        dpapi_master_key: key,
    });
});

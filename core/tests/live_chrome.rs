//! Tier-2 LIVE closed-loop validation against a real Chromium browser on this
//! macOS host (env-gated; skipped cleanly on CI and everywhere the artifacts or
//! opt-in are absent).
//!
//! The loop: real login Keychain -> real `<App> Safe Storage` password -> real
//! AES-128 key -> real `v10` `encrypted_value` from the browser's `Cookies` DB ->
//! plaintext. That is a genuine independent oracle — the browser (not this crate)
//! wrote the keychain entry and encrypted the cookie.
//!
//! Run with:
//!   `CHROMIUM_SAFESTORAGE_LIVE=1 cargo test -p chromium-safestorage-core --test live_chrome -- --nocapture`
//! Optional overrides:
//!   `CSS_LIVE_SERVICE`   (default "Brave Safe Storage")
//!   `CSS_LIVE_COOKIES`   (default the Brave `Default/Cookies` path)
//!
//! The test never prints the password or the key. It fails only if a recovered
//! real key fails to decrypt a real cookie (which would mean the derivation or
//! CBC path is wrong).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use chromium_safestorage_core::{derive_macos_key, RecoveredKey};

fn enabled() -> bool {
    std::env::var("CHROMIUM_SAFESTORAGE_LIVE").as_deref() == Ok("1")
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn service() -> String {
    std::env::var("CSS_LIVE_SERVICE").unwrap_or_else(|_| "Brave Safe Storage".to_string())
}

fn cookies_path() -> String {
    std::env::var("CSS_LIVE_COOKIES").unwrap_or_else(|_| {
        format!(
            "{}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
            home()
        )
    })
}

/// Read the Safe Storage password from the login Keychain (never printed).
fn safe_storage_password(svc: &str) -> Option<Vec<u8>> {
    let out = Command::new("security")
        .args(["find-generic-password", "-w", "-s", svc])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut pw = out.stdout;
    while pw.last() == Some(&b'\n') || pw.last() == Some(&b'\r') {
        pw.pop();
    }
    if pw.is_empty() {
        None
    } else {
        Some(pw)
    }
}

/// Pull one `v10` `encrypted_value` (hex) from a copy of the Cookies DB via sqlite3.
fn one_v10_cookie_hex(cookies: &str) -> Option<String> {
    // Copy first — the live DB may be WAL-locked by the running browser.
    let tmp = std::env::temp_dir().join("css_live_cookies.sqlite");
    std::fs::copy(cookies, &tmp).ok()?;
    let out = Command::new("sqlite3")
        .arg(&tmp)
        .arg("SELECT hex(encrypted_value) FROM cookies WHERE hex(encrypted_value) LIKE '763130%' LIMIT 1;")
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[test]
fn live_real_chrome_key_decrypts_a_real_cookie() {
    if !enabled() {
        eprintln!("skipping live test (set CHROMIUM_SAFESTORAGE_LIVE=1 to run)");
        return;
    }
    let svc = service();
    let Some(pw) = safe_storage_password(&svc) else {
        eprintln!("skipping: could not read '{svc}' from the Keychain (locked / not authorized)");
        return;
    };
    let cookies = cookies_path();
    let Some(blob_hex) = one_v10_cookie_hex(&cookies) else {
        eprintln!("skipping: no v10 cookie found in {cookies}");
        return;
    };

    let key = RecoveredKey::Aes128Cbc(derive_macos_key(&pw));
    let plaintext = key
        .decrypt_cookie(&hex(&blob_hex))
        .expect("real recovered key must decrypt a real v10 cookie (closed loop)");

    // Do not print the value; just prove the loop closed to well-formed bytes.
    assert!(
        !plaintext.is_empty(),
        "decrypted cookie plaintext must be non-empty"
    );
    eprintln!(
        "live closed loop OK: '{svc}' key decrypted a real v10 cookie ({} plaintext bytes)",
        plaintext.len()
    );
}

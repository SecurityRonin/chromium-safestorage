//! Forensic CLI behavior: the testable `report_*` decision functions and arg
//! parsing. The recovery/decryption oracles live in the core crate; here we
//! assert the CLI wiring (key hex, optional cookie decryption, verified
//! domain-hash stripping, refuse-don't-fabricate).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chromium_safestorage_forensic::{
    parse_hex, render_text, report_linux_v10, report_macos, report_windows, Cli, CliError, Command,
};
use clap::Parser;

const KEYCHAIN: &[u8] = include_bytes!("../../tests/data/css-test-login.keychain-db");
const LOGIN_PASSWORD: &[u8] = b"TestPass123!";
const CHROME_KEY_HEX: &str = "cf5505107fba7a67db54d90d9137187b";

// Python-cryptography v10 CBC cookie under the macOS key (SafeStorageDemoKey01).
const V10_MACOS_LEGACY: &str = "76313018b4b6b688fbe720da4ffdc408d035525b80dd7c7238689aff7c8491d0ccc3a4127901f54256f9b6414ca698617003ea";
const MACOS_COOKIE_PLAINTEXT: &str = "chromium-safe-storage-demo-cookie";

// dpapi-core impacket Windows vectors.
const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
const ENCRYPTED_KEY_B64: &str = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAz8Z9e40C+SoouK05ivQzGAAAAAAIAAAAAABBmAAAAAQAAIAAAAAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/AAAAAA6AAAAAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAA+t/5261X1EPXoNd8+fv91ognzpGyym/1M78vdGfOMphl2Zzre4QfJx4U0fUIzjosQAAAAP5yd3Yln699MQCEn7TqSfxp/Ba+vR7Ji1pSJ7TPr7zimD/5Slev0vK6H5r6Mq46ohSMEPLzAWzKvD5xxvJt1sA=";
const V10_GCM_COOKIE: &str = "7631300102030405060708090a0b0c1b5af334ffe7a1fe676c5ab453c8848232ab94aa630c69bae71883958ba23e4dfe4cc5faff526ce54b";
const GCM_COOKIE_PLAINTEXT: &str = "forensic-session-token-42";

// Linux v10 (peanuts) vector.
const V10_LINUX: &str = "76313033a6267625d550af7cb215522eeb831a3e706cf653757174abb98f186c703181";
const LINUX_COOKIE_PLAINTEXT: &str = "linux-peanuts-cookie";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- report_* decision functions ---

#[test]
fn macos_reports_key_and_decrypts_cookie() {
    let report = report_macos(
        KEYCHAIN,
        LOGIN_PASSWORD,
        "Chrome Safe Storage",
        Some(&hex(V10_MACOS_LEGACY)),
        None,
    )
    .expect("macos report");
    assert_eq!(report.source, "macos");
    assert_eq!(report.key_hex, CHROME_KEY_HEX);
    assert_eq!(
        report.cookie_plaintext.as_deref(),
        Some(MACOS_COOKIE_PLAINTEXT)
    );
}

#[test]
fn macos_without_cookie_reports_key_only() {
    let report =
        report_macos(KEYCHAIN, LOGIN_PASSWORD, "Chrome Safe Storage", None, None).expect("report");
    assert_eq!(report.key_hex, CHROME_KEY_HEX);
    assert!(report.cookie_plaintext.is_none());
}

#[test]
fn macos_locked_keychain_is_an_error_not_a_key() {
    let err =
        report_macos(KEYCHAIN, b"wrong-pw", "Chrome Safe Storage", None, None).expect_err("locked");
    assert!(matches!(
        err,
        CliError::Core(chromium_safestorage_forensic::chromium_safestorage_core::SafeStorageError::KeychainLocked)
    ));
}

#[test]
fn windows_reports_key_and_decrypts_gcm_cookie() {
    let json = format!("{{\"os_crypt\":{{\"encrypted_key\":\"{ENCRYPTED_KEY_B64}\"}}}}");
    let report = report_windows(json.as_bytes(), MASTER_KEY_HEX, Some(&hex(V10_GCM_COOKIE)))
        .expect("windows report");
    assert_eq!(report.source, "windows-v10");
    assert_eq!(report.key_hex.len(), 64); // AES-256
    assert_eq!(
        report.cookie_plaintext.as_deref(),
        Some(GCM_COOKIE_PLAINTEXT)
    );
}

#[test]
fn linux_v10_reports_key_and_decrypts_cookie() {
    let report = report_linux_v10(Some(&hex(V10_LINUX)), None).expect("linux v10 report");
    assert_eq!(report.source, "linux-v10");
    assert_eq!(report.key_hex, "fd621fe5a2b402539dfa147ca9272778");
    assert_eq!(
        report.cookie_plaintext.as_deref(),
        Some(LINUX_COOKIE_PLAINTEXT)
    );
}

#[test]
fn bad_master_key_hex_is_rejected() {
    let json = format!("{{\"os_crypt\":{{\"encrypted_key\":\"{ENCRYPTED_KEY_B64}\"}}}}");
    let err = report_windows(json.as_bytes(), "zz", None).expect_err("bad hex");
    assert!(matches!(err, CliError::BadHex(_)));
}

#[test]
fn parse_hex_accepts_prefix_and_rejects_junk() {
    assert_eq!(parse_hex("0x0a0b").unwrap(), vec![0x0a, 0x0b]);
    assert!(parse_hex("0a0").is_err());
    assert!(parse_hex("zz").is_err());
}

// --- arg parsing + rendering ---

#[test]
fn cli_parses_macos_subcommand() {
    let cli = Cli::try_parse_from([
        "safestore4n6",
        "macos",
        "--keychain",
        "/tmp/login.keychain-db",
        "--password",
        "pw",
    ])
    .expect("parse");
    assert!(matches!(cli.command, Command::Macos { .. }));
}

#[test]
fn cli_version_flag_supported() {
    let err = Cli::try_parse_from(["safestore4n6", "--version"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn render_shows_key_and_cookie() {
    let report = report_linux_v10(Some(&hex(V10_LINUX)), None).expect("report");
    let text = render_text(&report);
    assert!(text.contains("linux-v10"));
    assert!(text.contains(LINUX_COOKIE_PLAINTEXT));
}

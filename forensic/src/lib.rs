//! `safestore4n6` — forensic recovery of the Chromium 'Safe Storage' key and
//! decryption of Chrome/Edge/Brave cookies from acquired artifacts.
//!
//! Thin OS-dispatch front-end over [`chromium_safestorage_core`]: pick the source
//! OS (`macos` / `windows` / `linux-v10` / `linux-v11`), point it at the
//! artifacts, and it recovers the key and (optionally) decrypts one cookie value.
//! A locked keychain / absent master key is reported present-but-locked with a
//! non-zero exit — never a guessed key.
//!
//! Decision logic lives in this library (the testable `report_*` functions +
//! [`Cli::run`]); `main.rs` is a thin shell (Humble Object).

pub use chromium_safestorage_core;

use std::path::PathBuf;

use chromium_safestorage_core::{
    recover_key, strip_domain_hash, KeySource, RecoveredKey, SafeStorageError,
};
use clap::{Parser, Subcommand};
use serde::Serialize;

/// A typed CLI failure surfaced to the user (never a guessed key).
#[derive(Debug)]
pub enum CliError {
    /// A filesystem read failed (path + reason).
    Io(String),
    /// Bad hex input (e.g. the DPAPI master key).
    BadHex(String),
    /// An underlying recovery/decryption failure.
    Core(SafeStorageError),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(s) => write!(f, "io error: {s}"),
            CliError::BadHex(s) => write!(f, "bad hex: {s}"),
            CliError::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<SafeStorageError> for CliError {
    fn from(e: SafeStorageError) -> Self {
        CliError::Core(e)
    }
}

/// The CLI result: the recovered key and an optional decrypted cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The source OS / key version (`macos` / `windows-v10` / `linux-v10` / `linux-v11`).
    pub source: String,
    /// The recovered Safe Storage key, lowercase hex.
    pub key_hex: String,
    /// The decrypted cookie value (lossy UTF-8), if a `--cookie` blob was supplied.
    pub cookie_plaintext: Option<String>,
}

/// `safestore4n6` — recover Chromium Safe Storage keys from acquired artifacts.
#[derive(Debug, Parser)]
#[command(
    name = "safestore4n6",
    version,
    about = "Forensic Chromium 'Safe Storage' key recovery + cookie decryption"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Emit the report as JSON instead of a human line.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// macOS: read `<App> Safe Storage` from a `login.keychain-db`.
    Macos {
        /// Path to the `login.keychain-db` file.
        #[arg(long)]
        keychain: PathBuf,
        /// The account login password that unlocks the keychain.
        #[arg(long)]
        password: String,
        /// The generic-password service (default `Chrome Safe Storage`).
        #[arg(long, default_value = "Chrome Safe Storage")]
        service: String,
        /// Optional file holding one raw cookie `encrypted_value` to decrypt.
        #[arg(long)]
        cookie: Option<PathBuf>,
        /// Cookie host (`host_key`) — strips the verified 32-byte domain hash.
        #[arg(long)]
        host: Option<String>,
    },
    /// Windows: DPAPI-unwrap the `Local State` cookie key.
    Windows {
        /// Path to the browser `Local State` JSON file.
        #[arg(long)]
        local_state: PathBuf,
        /// The 64-byte DPAPI user master key, hex-encoded.
        #[arg(long = "master-key", value_name = "HEX")]
        master_key_hex: String,
        /// Optional file holding one raw cookie `encrypted_value` to decrypt.
        #[arg(long)]
        cookie: Option<PathBuf>,
    },
    /// Linux `v10`: the hard-coded `peanuts` key (no secret needed).
    LinuxV10 {
        /// Optional file holding one raw cookie `encrypted_value` to decrypt.
        #[arg(long)]
        cookie: Option<PathBuf>,
        /// Cookie host (`host_key`) — strips the verified 32-byte domain hash.
        #[arg(long)]
        host: Option<String>,
    },
    /// Linux `v11`: derive from a gnome-keyring / kwallet secret.
    LinuxV11 {
        /// The `<App> Safe Storage` secret read from the keyring.
        #[arg(long)]
        secret: String,
        /// Optional file holding one raw cookie `encrypted_value` to decrypt.
        #[arg(long)]
        cookie: Option<PathBuf>,
        /// Cookie host (`host_key`) — strips the verified 32-byte domain hash.
        #[arg(long)]
        host: Option<String>,
    },
}

/// Build a [`Report`] from a recovered key and an optional cookie blob, applying
/// verified domain-hash stripping when a host is given.
fn report_from(
    _source: &str,
    _key: &RecoveredKey,
    _cookie: Option<&[u8]>,
    _host: Option<&str>,
) -> Result<Report, CliError> {
    unimplemented!("report_from")
}

/// macOS report: recover from a keychain, optionally decrypt a cookie.
pub fn report_macos(
    keychain: &[u8],
    password: &[u8],
    service: &str,
    cookie: Option<&[u8]>,
    host: Option<&str>,
) -> Result<Report, CliError> {
    let key = recover_key(KeySource::MacOs {
        keychain,
        login_password: password,
        service,
    })?;
    report_from("macos", &key, cookie, host)
}

/// Windows report: DPAPI-unwrap the Local State key, optionally decrypt a cookie.
pub fn report_windows(
    local_state_json: &[u8],
    master_key_hex: &str,
    cookie: Option<&[u8]>,
) -> Result<Report, CliError> {
    let master_key = parse_hex(master_key_hex)?;
    let key = recover_key(KeySource::Windows {
        local_state_json,
        dpapi_master_key: &master_key,
    })?;
    report_from("windows-v10", &key, cookie, None)
}

/// Linux `v10` report: the hard-coded `peanuts` key, optionally decrypt a cookie.
pub fn report_linux_v10(cookie: Option<&[u8]>, host: Option<&str>) -> Result<Report, CliError> {
    let key = recover_key(KeySource::LinuxV10)?;
    report_from("linux-v10", &key, cookie, host)
}

/// Linux `v11` report: derive from the keyring secret, optionally decrypt a cookie.
pub fn report_linux_v11(
    secret: &[u8],
    cookie: Option<&[u8]>,
    host: Option<&str>,
) -> Result<Report, CliError> {
    let key = recover_key(KeySource::LinuxV11 {
        keyring_secret: secret,
    })?;
    report_from("linux-v11", &key, cookie, host)
}

/// Decode an ASCII hex string (optional `0x` prefix) into bytes, erroring loudly.
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, CliError> {
    let s = hex.strip_prefix("0x").unwrap_or(hex);
    if s.len() % 2 != 0 {
        return Err(CliError::BadHex(format!("odd length ({} chars)", s.len())));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, CliError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(CliError::BadHex(format!("non-hex byte {other:#04x}"))),
    }
}

impl Cli {
    /// Execute the parsed CLI, reading artifacts and dispatching to the OS path.
    pub fn run(&self) -> Result<Report, CliError> {
        match &self.command {
            Command::Macos {
                keychain,
                password,
                service,
                cookie,
                host,
            } => {
                let kc = read_bytes(keychain)?;
                let cookie_bytes = read_optional(cookie.as_deref())?;
                report_macos(
                    &kc,
                    password.as_bytes(),
                    service,
                    cookie_bytes.as_deref(),
                    host.as_deref(),
                )
            }
            Command::Windows {
                local_state,
                master_key_hex,
                cookie,
            } => {
                let ls = read_bytes(local_state)?;
                let cookie_bytes = read_optional(cookie.as_deref())?;
                report_windows(&ls, master_key_hex, cookie_bytes.as_deref())
            }
            Command::LinuxV10 { cookie, host } => {
                let cookie_bytes = read_optional(cookie.as_deref())?;
                report_linux_v10(cookie_bytes.as_deref(), host.as_deref())
            }
            Command::LinuxV11 {
                secret,
                cookie,
                host,
            } => {
                let cookie_bytes = read_optional(cookie.as_deref())?;
                report_linux_v11(secret.as_bytes(), cookie_bytes.as_deref(), host.as_deref())
            }
        }
    }
}

fn read_bytes(path: &std::path::Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

fn read_optional(path: Option<&std::path::Path>) -> Result<Option<Vec<u8>>, CliError> {
    match path {
        Some(p) => Ok(Some(read_bytes(p)?)),
        None => Ok(None),
    }
}

/// Render a [`Report`] as a human-readable line.
#[must_use]
pub fn render_text(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = format!("[{}] key={}\n", report.source, report.key_hex);
    if let Some(pt) = &report.cookie_plaintext {
        let _ = writeln!(out, "cookie={pt}");
    }
    out
}

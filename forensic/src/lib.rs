//! `safestore4n6` — forensic recovery of the Chromium 'Safe Storage' key and
//! decryption of Chrome/Edge/Brave cookies from acquired artifacts.
//!
//! Thin OS-dispatch front-end over [`chromium_safestorage_core`]: pick the source
//! OS (`macos` / `windows` / `linux-v10` / `linux-v11`), point it at the
//! artifacts, and it recovers the key and (optionally) decrypts one cookie value.
//! A locked keychain / absent master key is reported present-but-locked with a
//! non-zero exit — never a guessed key.
//!
//! Decision logic lives in this library (`recover` + [`Cli::run`]); `main.rs` is
//! a thin shell (Humble Object).

pub use chromium_safestorage_core;

use std::path::PathBuf;

use chromium_safestorage_core::SafeStorageError;
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
    /// The decrypted cookie value, if a `--cookie` blob was supplied.
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

impl Cli {
    /// Execute the parsed CLI, returning the recovered report or a typed error.
    pub fn run(&self) -> Result<Report, CliError> {
        let _ = &self.command;
        unimplemented!("Cli::run")
    }
}

/// Render a [`Report`] as a human-readable line.
#[must_use]
pub fn render_text(report: &Report) -> String {
    let mut out = format!("[{}] key={}\n", report.source, report.key_hex);
    if let Some(pt) = &report.cookie_plaintext {
        out.push_str(&format!("cookie={pt}\n"));
    }
    out
}

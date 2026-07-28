//! The single error type for Safe Storage key recovery and cookie decryption.
//!
//! Every failure is a loud, typed error — a locked keychain, an absent DPAPI
//! master key, a wrong key, or a corrupt blob. The library never fabricates a
//! key or a plaintext (see the crate docs / SECURITY.md).

use std::fmt;

/// A recovery or decryption failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SafeStorageError {
    /// The macOS keychain parsed but the login password did not unlock it —
    /// present-but-locked, never a fabricated secret.
    KeychainLocked,
    /// The keychain could not be parsed / read (carries the reader's reason).
    Keychain(String),
    /// No generic-password entry matched the requested `service` (e.g.
    /// `Chrome Safe Storage`). Carries the service that was searched for.
    ServiceNotFound(String),
    /// Windows DPAPI recovery of the `os_crypt.encrypted_key` failed (carries
    /// the underlying `dpapi-core` reason). A wrong/absent master key lands here
    /// — never a guessed key.
    Dpapi(String),
    /// The `Local State` JSON has no `os_crypt.encrypted_key` string field.
    NoEncryptedKey,
    /// A cookie value is too short to carry a version prefix + ciphertext.
    CookieTooShort(usize),
    /// A cookie value did not start with a recognised prefix; carries the actual
    /// leading bytes (hex) so the analyst can identify the encoding.
    UnknownCookiePrefix(String),
    /// AES-128-CBC decryption produced invalid PKCS#7 padding — the standard
    /// signal of a wrong key (macOS / Linux path).
    BadPadding,
    /// AES-256-GCM authentication failed — a wrong key or a corrupt/forged blob
    /// (Windows path).
    GcmDecryptFailed,
}

impl fmt::Display for SafeStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafeStorageError::KeychainLocked => write!(
                f,
                "keychain present but LOCKED: the login password did not unlock it"
            ),
            SafeStorageError::Keychain(e) => write!(f, "keychain read error: {e}"),
            SafeStorageError::ServiceNotFound(svc) => {
                write!(f, "no keychain entry for service '{svc}'")
            }
            SafeStorageError::Dpapi(e) => write!(f, "DPAPI recovery failed: {e}"),
            SafeStorageError::NoEncryptedKey => {
                write!(f, "Local State has no os_crypt.encrypted_key")
            }
            SafeStorageError::CookieTooShort(n) => {
                write!(f, "cookie value too short ({n} bytes) for a version prefix")
            }
            SafeStorageError::UnknownCookiePrefix(bytes) => {
                write!(f, "unrecognised cookie prefix (leading bytes: {bytes})")
            }
            SafeStorageError::BadPadding => {
                write!(f, "AES-128-CBC padding invalid (wrong key or corrupt data)")
            }
            SafeStorageError::GcmDecryptFailed => {
                write!(
                    f,
                    "AES-256-GCM authentication failed (wrong key or corrupt data)"
                )
            }
        }
    }
}

impl std::error::Error for SafeStorageError {}

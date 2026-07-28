//! The recovered key and the cookie/login decryption it performs.
//!
//! [`RecoveredKey`] is the secure-by-design output of recovery: it carries the
//! key **and the cipher family it belongs to**, so a caller cannot mismatch a
//! macOS AES-128-CBC key with a Windows AES-256-GCM cookie. Decrypt through
//! [`RecoveredKey::decrypt_cookie`] and the right algorithm is chosen for you.
//!
//! Wire format of an `encrypted_value` from a Chromium `Cookies` DB:
//!
//! - macOS / Linux: `"v10"`/`"v11"` prefix + AES-128-CBC ciphertext, IV = 16
//!   space bytes (`0x20`), PKCS#7 padding.
//! - Windows: `"v10"`/`"v20"` prefix + 12-byte GCM nonce + ciphertext + 16-byte
//!   tag (AES-256-GCM), delegated to `dpapi-core`.
//!
//! Newer Chromium prepends a 32-byte `SHA-256(host_key)` domain hash to the
//! decrypted cookie plaintext; [`strip_domain_hash`] removes it **after
//! verifying** it against the cookie's host, never by blindly cutting 32 bytes.

use crate::error::SafeStorageError;

/// A recovered Safe Storage key, tagged with its cipher family.
///
/// The two variants are the complete set of Chromium OSCrypt cipher families
/// (macOS/Linux AES-128-CBC, Windows AES-256-GCM), so this is intentionally
/// exhaustive — callers match both arms to read the key.
#[derive(Clone, PartialEq, Eq)]
pub enum RecoveredKey {
    /// macOS / Linux: 16-byte AES-128 key; cookies are AES-128-CBC (`v10`/`v11`).
    Aes128Cbc([u8; 16]),
    /// Windows: 32-byte AES-256 key; cookies are AES-256-GCM (`v10`/`v20`).
    Aes256Gcm([u8; 32]),
}

impl std::fmt::Debug for RecoveredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print raw key material in Debug output.
        match self {
            RecoveredKey::Aes128Cbc(_) => write!(f, "RecoveredKey::Aes128Cbc([16 bytes redacted])"),
            RecoveredKey::Aes256Gcm(_) => write!(f, "RecoveredKey::Aes256Gcm([32 bytes redacted])"),
        }
    }
}

impl RecoveredKey {
    /// The raw key bytes (16 for AES-128, 32 for AES-256).
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        match self {
            RecoveredKey::Aes128Cbc(k) => k,
            RecoveredKey::Aes256Gcm(k) => k,
        }
    }

    /// Lowercase-hex rendering of the key (for display / logging by the analyst).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.key_bytes().len() * 2);
        use std::fmt::Write as _;
        for b in self.key_bytes() {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Decrypt one raw `encrypted_value` from a Chromium `Cookies` DB.
    ///
    /// The cipher is chosen from the key family, not guessed from the prefix, so
    /// this cannot apply CBC to a GCM blob or vice-versa. A wrong key or a
    /// corrupt/forged blob surfaces as a typed error — never a fabricated
    /// plaintext.
    pub fn decrypt_cookie(&self, _encrypted_value: &[u8]) -> Result<Vec<u8>, SafeStorageError> {
        unimplemented!("RecoveredKey::decrypt_cookie")
    }
}

/// Remove the 32-byte `SHA-256(host_key)` domain-hash prefix newer Chromium
/// prepends to a decrypted cookie value — **only if it matches** this cookie's
/// host. When it does not match (older schema, wrong host), the plaintext is
/// returned unchanged rather than losing 32 real bytes.
#[must_use]
pub fn strip_domain_hash<'a>(_plaintext: &'a [u8], _host_key: &[u8]) -> &'a [u8] {
    unimplemented!("strip_domain_hash")
}

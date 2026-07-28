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

use aes::Aes128;
use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

use crate::error::SafeStorageError;

/// AES-128-CBC IV Chromium uses for cookie values on macOS/Linux: 16 space bytes.
const CBC_IV: [u8; 16] = [0x20; 16];

type Aes128CbcDec = Decryptor<Aes128>;

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
    pub fn decrypt_cookie(&self, encrypted_value: &[u8]) -> Result<Vec<u8>, SafeStorageError> {
        match self {
            RecoveredKey::Aes128Cbc(key) => decrypt_cbc(encrypted_value, key),
            RecoveredKey::Aes256Gcm(key) => decrypt_gcm(encrypted_value, key),
        }
    }
}

/// Strip the recognised `v10`/`v11` prefix, or fail loudly showing the bytes.
fn strip_cbc_prefix(value: &[u8]) -> Result<&[u8], SafeStorageError> {
    if value.len() < 3 {
        return Err(SafeStorageError::CookieTooShort(value.len()));
    }
    match &value[..3] {
        b"v10" | b"v11" => Ok(&value[3..]),
        _ => Err(SafeStorageError::UnknownCookiePrefix(hex_prefix(value))),
    }
}

/// macOS / Linux: `v10`/`v11` + AES-128-CBC (IV = 16 spaces, PKCS#7).
fn decrypt_cbc(value: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, SafeStorageError> {
    let ciphertext = strip_cbc_prefix(value)?;
    Aes128CbcDec::new(key.into(), &CBC_IV.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| SafeStorageError::BadPadding)
}

/// Windows: `v10`/`v20` AES-256-GCM, delegated to `dpapi-core`'s vetted path.
fn decrypt_gcm(value: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, SafeStorageError> {
    use dpapi_core::ChromeCookieEncoding;
    match dpapi_core::detect_chrome_cookie_encoding(value) {
        ChromeCookieEncoding::V10 { nonce, ciphertext }
        | ChromeCookieEncoding::V20 { nonce, ciphertext } => {
            dpapi_core::decrypt_v10_cookie(&nonce, &ciphertext, key)
                .map_err(|_| SafeStorageError::GcmDecryptFailed)
        }
        ChromeCookieEncoding::DpapiBlob(_) | ChromeCookieEncoding::Raw => {
            Err(SafeStorageError::UnknownCookiePrefix(hex_prefix(value)))
        }
    }
}

/// Lowercase-hex of up to the first 4 bytes, for an "unknown prefix" diagnostic.
fn hex_prefix(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in value.iter().take(4) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Remove the 32-byte `SHA-256(host_key)` domain-hash prefix newer Chromium
/// prepends to a decrypted cookie value — **only if it matches** this cookie's
/// host. When it does not match (older schema, wrong host), the plaintext is
/// returned unchanged rather than losing 32 real bytes.
#[must_use]
pub fn strip_domain_hash<'a>(plaintext: &'a [u8], host_key: &[u8]) -> &'a [u8] {
    if plaintext.len() >= 32 {
        let want = Sha256::digest(host_key);
        if plaintext[..32] == want[..] {
            return &plaintext[32..];
        }
    }
    plaintext
}

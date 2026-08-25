//! Vault error type.
//!
//! No secret material ever appears in these messages. The crypto failures all
//! collapse into a single [`Error::Auth`] so an attacker cannot tell a wrong
//! password apart from a tampered file or a missing keyfile.

use thiserror::Error;

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by vault operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Filesystem or other IO failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file does not start with the expected magic bytes.
    #[error("not a vault file (bad magic)")]
    BadMagic,

    /// The on-disk format version is newer than this build understands.
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),

    /// The stored KDF identifier is not one this build implements.
    #[error("unsupported kdf id {0}")]
    UnsupportedKdf(u8),

    /// The stored AEAD identifier is not one this build implements.
    #[error("unsupported aead id {0}")]
    UnsupportedAead(u8),

    /// The header is truncated or otherwise not parseable.
    #[error("vault header is malformed or truncated")]
    MalformedHeader,

    /// Decryption or tag verification failed. Covers a wrong password, a
    /// missing or wrong keyfile, and any tampering with header or ciphertext.
    #[error("authentication failed: wrong password, wrong keyfile, or corrupted vault")]
    Auth,

    /// The vault was created with a keyfile but none was supplied.
    #[error("this vault requires a keyfile")]
    KeyfileRequired,

    /// A keyfile was supplied for a vault that was created without one.
    #[error("this vault was not created with a keyfile")]
    UnexpectedKeyfile,

    /// Key derivation failed inside Argon2.
    #[error("key derivation failed")]
    Kdf,

    /// The supplied Argon2 parameters are below the algorithm minimums.
    #[error("invalid argon2 parameters")]
    InvalidParams,

    /// The stored Argon2 parameters exceed the read-path safety ceiling.
    /// Rejected before any key derivation to avoid resource exhaustion.
    #[error("argon2 parameters exceed the safe ceiling")]
    ParamsOutOfRange,

    /// The plaintext entry map could not be encoded.
    #[error("failed to encode entries")]
    Serialize,

    /// The decrypted bytes were not a valid entry map.
    #[error("failed to decode entries")]
    Deserialize,

    /// The system secure random source was unavailable.
    #[error("secure random source unavailable")]
    Random,

    /// No entry exists for the given id.
    #[error("entry not found")]
    NotFound,
}

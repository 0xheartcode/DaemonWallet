//! A native encrypted secret vault.
//!
//! This crate stores arbitrary secret blobs plus metadata, encrypted at rest
//! and decrypted into locked memory only while unlocked. It follows KeePassXC
//! principles (Argon2id key derivation, authenticated encryption, mlock-ed
//! plaintext) but does not use the KDBX file format. The on-disk layout is a
//! small self-describing binary container defined in this crate.
//!
//! The store is byte-generic and wallet-agnostic. An entry is an id mapped to
//! opaque secret bytes and a [`Meta`] record. Nothing here knows about wallets,
//! keys, or any particular use of the bytes.
//!
//! # Cryptography
//!
//! - Key derivation: Argon2id, 32-byte output, parameters stored in the file
//!   and honored on read.
//! - Encryption: XChaCha20-Poly1305 with a 24-byte random nonce. The entire
//!   file header is the associated data, so tampering with any header field
//!   fails the tag check.
//! - Optional keyfile: BLAKE2b-256 of the keyfile bytes becomes the Argon2id
//!   secret (pepper). Without it the derived key differs and the open fails.
//!
//! # Example
//!
//! ```no_run
//! use daemon_wallet_vault::{KdfParams, Meta, Vault};
//!
//! # fn main() -> daemon_wallet_vault::Result<()> {
//! let path = "secrets.vault";
//! let mut vault = Vault::create(path, b"a strong passphrase", None, KdfParams::default())?;
//! vault.put("api-token", b"s3cr3t-bytes", Meta::new("Service API token"));
//! vault.save()?;
//!
//! let reopened = Vault::open(path, b"a strong passphrase", None)?;
//! assert_eq!(reopened.get("api-token").map(|e| e.secret()), Some(&b"s3cr3t-bytes"[..]));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod crypto;
mod error;
mod format;
mod secret;
mod strength;
mod vault;

pub use error::{Error, Result};
pub use format::{FORMAT_VERSION, KdfParams};
pub use secret::SecretBytes;
pub use strength::{StrengthPolicy, StrengthReport, assess_password};
pub use vault::{Entry, Meta, Vault};

//! EVM-specific error type.
//!
//! These are the failures the EVM layer can hit on its own terms (a malformed
//! address, a bad private key, a signature it cannot parse). At the
//! [`crate::EvmChain`] boundary they fold into the neutral
//! [`daemon_wallet_core::Error`] through the [`From`] impl below, so the
//! chain-agnostic core never sees an EVM-shaped error. As everywhere in this
//! project, no secret material appears in a message.

use thiserror::Error;

/// Result alias for the EVM layer.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the EVM implementation.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An address string was not valid EVM hex (or failed its checksum).
    #[error("invalid evm address")]
    InvalidAddress,

    /// A private key was not a valid secp256k1 scalar.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Raw signature bytes were not a well-formed secp256k1 signature.
    #[error("invalid signature encoding")]
    InvalidSignature,

    /// A signing payload could not be encoded or decoded.
    #[error("invalid signing payload")]
    InvalidPayload,

    /// The underlying signer backend refused or failed.
    #[error("signer failed")]
    Signer,
}

impl From<Error> for daemon_wallet_core::Error {
    /// Fold an EVM error into the neutral core error at the crate boundary.
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidAddress => daemon_wallet_core::Error::AddressParse,
            Error::InvalidPrivateKey => daemon_wallet_core::Error::Derivation,
            Error::InvalidSignature | Error::InvalidPayload | Error::Signer => {
                daemon_wallet_core::Error::Signing
            }
        }
    }
}

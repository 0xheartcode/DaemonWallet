//! The EVM implementation of [`daemon_wallet_core::Chain`], plus the boundary
//! conversions between core's neutral types and alloy's.
//!
//! [`EvmChain`] is what makes an EVM account derivable and signable from the
//! chain-agnostic [`daemon_wallet_core::Wallet`]. The application constructs one
//! and registers it:
//!
//! ```no_run
//! use daemon_wallet_core::{ChainKind, ChainRegistry};
//! use daemon_wallet_evm::EvmChain;
//!
//! let mut chains = ChainRegistry::new();
//! chains.register(Box::new(EvmChain::new()));
//! assert!(chains.contains(ChainKind::Evm));
//! ```
//!
//! A future Solana or Bitcoin crate is the same pattern: implement
//! [`daemon_wallet_core::Chain`] for its own type, convert to and from
//! [`daemon_wallet_core::ChainAddress`] at its own boundary, and register it.
//! Core is never edited.
//!
//! # The neutral/alloy boundary
//!
//! Core stores addresses as the neutral [`daemon_wallet_core::ChainAddress`]
//! string. This module is the only place EVM addresses cross between that
//! neutral form and alloy's [`Address`]: [`to_alloy_address`] parses inbound,
//! [`from_alloy_address`] renders outbound (checksummed). Nothing above this
//! crate ever sees an alloy type.

use crate::error::Result as EvmResult;
use crate::signer::{Signature, TransactionRequest, TypedDataRequest};
use alloy_primitives::Address;
use daemon_wallet_core::{
    AccountSecret, Chain, ChainAddress, ChainKind, DerivationPath, Result, SigningPayload,
};

/// The EVM family's [`Chain`] implementation.
///
/// It is stateless: derivation and signing depend only on the secret and path
/// passed in. It is registered as `Box<dyn Chain>` and dispatched on
/// [`ChainKind::Evm`].
#[derive(Clone, Copy, Debug, Default)]
pub struct EvmChain;

impl EvmChain {
    /// Construct the EVM chain implementation.
    pub fn new() -> Self {
        EvmChain
    }
}

impl Chain for EvmChain {
    fn kind(&self) -> ChainKind {
        ChainKind::Evm
    }

    fn derive_address(&self, seed_material: &[u8], path: &DerivationPath) -> Result<ChainAddress> {
        let _ = (seed_material, path);
        todo!()
    }

    fn import_address(&self, private_key: &[u8]) -> Result<ChainAddress> {
        let _ = private_key;
        todo!()
    }

    fn sign(&self, secret: AccountSecret<'_>, payload: &SigningPayload) -> Result<Vec<u8>> {
        let _ = (secret, payload);
        todo!()
    }

    fn parse_address(&self, text: &str) -> Result<ChainAddress> {
        let _ = text;
        todo!()
    }

    fn format_address(&self, address: &ChainAddress) -> String {
        let _ = address;
        todo!()
    }
}

/// Parse a neutral [`ChainAddress`] into an alloy [`Address`].
///
/// Fails with [`crate::Error::InvalidAddress`] if the text is not valid EVM hex.
pub fn to_alloy_address(address: &ChainAddress) -> EvmResult<Address> {
    let _ = address;
    todo!()
}

/// Render an alloy [`Address`] as a neutral, EIP-55 checksummed [`ChainAddress`].
pub fn from_alloy_address(address: &Address) -> ChainAddress {
    let _ = address;
    todo!()
}

/// Encode a [`TransactionRequest`] into a chain-tagged [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::Transaction`], ready for
/// [`daemon_wallet_core::Wallet::sign`].
///
/// Fails with [`crate::Error::InvalidPayload`] if the transaction cannot be
/// encoded.
pub fn transaction_payload(tx: &TransactionRequest) -> EvmResult<SigningPayload> {
    let _ = tx;
    todo!()
}

/// Wrap an arbitrary message as a [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::Message`] (EIP-191 `personal_sign`).
pub fn message_payload(message: &[u8]) -> SigningPayload {
    let _ = message;
    todo!()
}

/// Wrap an EIP-712 [`TypedDataRequest`] as a [`SigningPayload`] with
/// [`daemon_wallet_core::PayloadKind::TypedData`].
pub fn typed_data_payload(typed: &TypedDataRequest) -> SigningPayload {
    let _ = typed;
    todo!()
}

/// Reconstruct a typed [`Signature`] from the raw bytes a
/// [`daemon_wallet_core::Wallet::sign`] call returned for an EVM account.
///
/// Fails with [`crate::Error::InvalidSignature`] if the bytes are not a
/// well-formed 65-byte `r ‖ s ‖ v` signature.
pub fn parse_signature(bytes: &[u8]) -> EvmResult<Signature> {
    let _ = bytes;
    todo!()
}

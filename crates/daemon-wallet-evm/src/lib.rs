//! The EVM implementation of the chain-agnostic [`daemon_wallet_core`] model.
//!
//! `daemon-wallet-core` owns how a wallet is organised and persisted but knows
//! nothing about any chain. This crate supplies the EVM half: it implements
//! [`daemon_wallet_core::Chain`] as [`EvmChain`], provides the EVM transaction
//! and signature types and the signer trait, and hosts a pinned EVM chain-info
//! registry with a safe external merge.
//!
//! # Dependency direction
//!
//! `vault -> core -> evm`. This crate depends on `daemon-wallet-core`,
//! `daemon-wallet-vault`, and `alloy-primitives`. Core does not depend on it or
//! on alloy; the coupling points one way only. Everything alloy-shaped is
//! confined here, and the neutral/alloy conversions live in [`evm_chain`].
//!
//! # Wiring it up
//!
//! Build an [`EvmChain`], register it into a
//! [`daemon_wallet_core::ChainRegistry`], and hand that registry to
//! [`daemon_wallet_core::Wallet`]. From then on the wallet routes every EVM
//! account's derivation and signing through this crate without ever naming an
//! alloy type itself.

#![forbid(unsafe_code)]

pub mod chains;
pub mod error;
pub mod evm_chain;
pub mod signer;

pub use chains::{BUILTIN_CHAIN_IDS, ChainInfo, ChainInfoRegistry, MergeReport};
pub use error::{Error, Result};
pub use evm_chain::{
    EvmChain, from_alloy_address, message_payload, parse_signature, to_alloy_address,
    transaction_payload, typed_data_payload,
};
pub use signer::{
    EvmSigner, FeeParams, LocalSigner, Signature, TransactionRequest, TypedDataRequest,
};

//! The EVM signing surface: transaction and signature types, plus the signer
//! trait and a concrete local signer.
//!
//! # Alloy surface
//!
//! The EVM layer uses `alloy-primitives` for value types only: [`Address`],
//! [`U256`], [`B256`], and [`Bytes`]. It does not pull in `alloy-consensus` or
//! the RPC stack. Actual signing is expressed through the [`EvmSigner`] trait;
//! [`LocalSigner`] is the concrete implementation an implementer wires
//! `alloy-signer-local` into, taking its key material as vault-held
//! [`daemon_wallet_vault::SecretBytes`].
//!
//! # The three signing modes
//!
//! - [`EvmSigner::sign_transaction`] over a [`TransactionRequest`].
//! - [`EvmSigner::sign_message`] over arbitrary bytes (EIP-191 `personal_sign`).
//! - [`EvmSigner::sign_typed_data`] over a [`TypedDataRequest`] (EIP-712).
//!
//! All three reduce to signing a 32-byte digest via [`EvmSigner::sign_hash`], so
//! the digest-construction rules live in one auditable place.

use crate::error::Result;
use alloy_primitives::{Address, B256, Bytes, U256};
use daemon_wallet_vault::SecretBytes;

/// The gas/fee shape of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeParams {
    /// Pre-EIP-1559 legacy pricing.
    Legacy {
        /// The gas price the sender is willing to pay.
        gas_price: U256,
    },
    /// EIP-1559 dynamic-fee pricing.
    Eip1559 {
        /// Maximum total fee per gas.
        max_fee_per_gas: U256,
        /// Maximum priority (tip) fee per gas.
        max_priority_fee_per_gas: U256,
    },
}

/// A concrete EVM transaction to be signed.
///
/// This is the EVM layer's own transaction shape rather than an alloy consensus
/// type, so the crate depends only on `alloy-primitives`. The implementer maps
/// it onto a signed envelope when wiring the real signer. To sign it through a
/// [`daemon_wallet_core::Wallet`], encode it into a
/// [`daemon_wallet_core::SigningPayload`] with [`crate::transaction_payload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRequest {
    /// The EIP-155 chain id this transaction is bound to. Binding the chain id
    /// into every signature is what stops a signed transaction being replayed
    /// on a different chain.
    pub chain_id: u64,
    /// The sender's next nonce.
    pub nonce: u64,
    /// The recipient, or `None` for a contract-creation transaction.
    pub to: Option<Address>,
    /// The value transferred, in wei.
    pub value: U256,
    /// The calldata / init code.
    pub input: Bytes,
    /// The gas limit.
    pub gas_limit: u64,
    /// The fee pricing.
    pub fee: FeeParams,
}

/// An EIP-712 typed-data request.
///
/// The payload is carried as the raw JSON a dapp supplies. Parsing it and
/// computing the domain separator and struct hash is the signer backend's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedDataRequest {
    /// The canonical EIP-712 JSON document (`types`, `domain`, `primaryType`,
    /// `message`).
    pub raw_json: String,
}

/// A secp256k1 signature over an EVM payload.
///
/// Stored in structured `(r, s, y_parity)` form. [`Signature::to_rsv`] renders
/// the 65-byte `r ‖ s ‖ v` layout most EVM tooling expects. This is the typed
/// form that [`crate::parse_signature`] reconstructs from the raw bytes a
/// [`daemon_wallet_core::Wallet::sign`] call returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
    /// The recovery bit (`v = 27 + y_parity` in legacy encodings).
    pub y_parity: bool,
}

impl Signature {
    /// Render the signature as 65 bytes: `r` (32) ‖ `s` (32) ‖ `v` (1), where
    /// `v` is `27` or `28`.
    pub fn to_rsv(&self) -> [u8; 65] {
        todo!()
    }
}

/// A signer bound to exactly one account's secret.
///
/// Implementations hold (or can reach) the private key for a single address and
/// know nothing about the wallet, the vault, or other accounts.
pub trait EvmSigner {
    /// The address this signer produces signatures for.
    fn address(&self) -> Address;

    /// Sign a raw 32-byte digest. The higher-level methods reduce to this.
    fn sign_hash(&self, hash: B256) -> Result<Signature>;

    /// Assemble, hash, and sign a transaction.
    fn sign_transaction(&self, tx: &TransactionRequest) -> Result<Signature>;

    /// Sign an arbitrary message under EIP-191 (`personal_sign`).
    fn sign_message(&self, message: &[u8]) -> Result<Signature>;

    /// Sign an EIP-712 typed-data payload.
    fn sign_typed_data(&self, typed: &TypedDataRequest) -> Result<Signature>;
}

/// A concrete [`EvmSigner`] backed by a private key held in vault memory.
///
/// This is the anchor for wiring `alloy-signer-local`: build one from the
/// secret bytes the wallet fetched from the vault, then sign. The key stays
/// inside the signer and is never exposed.
pub struct LocalSigner {
    /// The address this signer controls, cached from the key.
    #[allow(dead_code)]
    address: Address,
}

impl LocalSigner {
    /// Build a signer from vault-held secret key bytes.
    ///
    /// Fails with [`crate::Error::InvalidPrivateKey`] if the bytes are not a
    /// valid secp256k1 scalar.
    pub fn from_secret(secret: &SecretBytes) -> Result<Self> {
        let _ = secret;
        todo!()
    }
}

impl EvmSigner for LocalSigner {
    fn address(&self) -> Address {
        todo!()
    }

    fn sign_hash(&self, hash: B256) -> Result<Signature> {
        let _ = hash;
        todo!()
    }

    fn sign_transaction(&self, tx: &TransactionRequest) -> Result<Signature> {
        let _ = tx;
        todo!()
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let _ = message;
        todo!()
    }

    fn sign_typed_data(&self, typed: &TypedDataRequest) -> Result<Signature> {
        let _ = typed;
        todo!()
    }
}

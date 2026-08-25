//! Stable wire data-transfer objects.
//!
//! These are the shapes that actually cross the wire. The organisational types
//! they mirror ([`daemon_wallet_core::Account`], [`daemon_wallet_core::Group`])
//! come from the chain-agnostic core, and a signature comes from the EVM crate;
//! the `From` conversions here map those into wire form so a client never
//! depends on the internals directly.
//!
//! Addresses are carried in core's chain-neutral [`daemon_wallet_core::ChainAddress`]
//! form, so the wire vocabulary is not tied to any one chain's address type. A
//! transaction, by contrast, is inherently chain-specific, so [`TxRequestDto`]
//! keeps EVM fields (alloy [`Address`], [`U256`], [`Bytes`]).
//!
//! Ids that are opaque newtypes in the domain ([`daemon_wallet_core::AccountId`]
//! and friends) are flattened to plain `String`s here, because the wire has no
//! reason to care about their type identity and a string is the most portable
//! representation across languages.

use alloy_primitives::{Address, Bytes, U256};
use daemon_wallet_core::{ChainAddress, ChainKind};
use serde::{Deserialize, Serialize};

/// A dapp origin, for example `https://app.uniswap.org`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin(pub String);

/// How a client points at an account.
///
/// A dapp usually knows only the address, while a first-party UI may prefer the
/// stable id; both are accepted and resolved on the daemon side. The address
/// form uses the chain-neutral [`ChainAddress`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRef {
    /// Reference by the account's stable id.
    Id(String),
    /// Reference by the account's chain-neutral address.
    Address(ChainAddress),
}

/// The provenance of an account, flattened for the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSourceKind {
    /// Derived from a seed.
    Derived,
    /// Backed by an imported private key.
    Imported,
}

/// Wire view of an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDto {
    /// The account's stable id, as a string.
    pub id: String,
    /// The chain family this account belongs to.
    pub chain: ChainKind,
    /// The account's chain-neutral address.
    pub address: ChainAddress,
    /// Display label.
    pub label: String,
    /// Whether the account is hidden from normal listings.
    pub hidden: bool,
    /// Whether the account is derived or imported.
    pub source_kind: AccountSourceKind,
    /// The id of the group the account is filed under, as a string.
    pub group: String,
    /// User tags.
    pub tags: Vec<String>,
}

/// Wire view of a group tree node.
///
/// Structural links stay as ids, so a client can rebuild the tree from a flat
/// `Vec<GroupDto>` exactly as the domain stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDto {
    /// This group's id, as a string.
    pub id: String,
    /// The parent group's id, or `None` for the root.
    pub parent: Option<String>,
    /// Child group ids, in order.
    pub children: Vec<String>,
    /// Display name.
    pub name: String,
    /// Free-form notes.
    pub notes: String,
    /// User tags.
    pub tags: Vec<String>,
}

/// What a parked approval is asking the user to authorise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// An origin wants to connect.
    Connect,
    /// A transaction signature is requested.
    SignTransaction,
    /// An EIP-712 typed-data signature is requested.
    SignTypedData,
    /// An EIP-191 `personal_sign` is requested.
    PersonalSign,
}

/// Wire view of a request parked for human approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDto {
    /// The id of the parked request, to be echoed in approve/reject.
    pub id: super::RequestId,
    /// The origin that made the request.
    pub origin: Origin,
    /// What is being asked for.
    pub kind: ApprovalKind,
    /// The account involved, when the request names one, as a neutral address.
    pub account: Option<ChainAddress>,
    /// A short human-readable summary the UI can show verbatim.
    pub summary: String,
}

/// Wire view of daemon status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDto {
    /// Whether the wallet is currently locked.
    pub locked: bool,
    /// The daemon's [`super::PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// How many accounts the wallet holds.
    pub account_count: usize,
    /// The currently connected origins.
    pub connected_origins: Vec<Origin>,
}

/// Wire view of an EVM transaction to be signed.
///
/// A transaction is inherently chain-specific, so this DTO keeps EVM fields.
/// Fields the daemon can fill in itself (nonce, gas, fees) are optional so a
/// dapp may leave them unset and let the daemon populate them before showing
/// the approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRequestDto {
    /// The EIP-155 chain id the transaction is bound to.
    pub chain_id: u64,
    /// The sender nonce, or `None` to let the daemon choose.
    pub nonce: Option<u64>,
    /// The recipient, or `None` for contract creation.
    pub to: Option<Address>,
    /// Value transferred, in wei.
    pub value: U256,
    /// Calldata / init code.
    pub input: Bytes,
    /// Gas limit, or `None` to let the daemon estimate.
    pub gas_limit: Option<u64>,
    /// EIP-1559 max fee per gas, when using dynamic fees.
    pub max_fee_per_gas: Option<U256>,
    /// EIP-1559 max priority fee per gas, when using dynamic fees.
    pub max_priority_fee_per_gas: Option<U256>,
    /// Legacy gas price, when using legacy pricing.
    pub gas_price: Option<U256>,
}

/// Wire view of an EIP-712 typed-data payload: the raw canonical JSON document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataDto {
    /// The canonical EIP-712 JSON (`types`, `domain`, `primaryType`, `message`).
    pub raw_json: String,
}

/// Wire view of a secp256k1 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDto {
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
    /// The recovery bit.
    pub y_parity: bool,
}

impl From<&daemon_wallet_core::Account> for AccountDto {
    /// Flatten a core account into its wire view.
    fn from(value: &daemon_wallet_core::Account) -> Self {
        let _ = value;
        todo!()
    }
}

impl From<&daemon_wallet_core::Group> for GroupDto {
    /// Flatten a core group node into its wire view.
    fn from(value: &daemon_wallet_core::Group) -> Self {
        let _ = value;
        todo!()
    }
}

impl From<&daemon_wallet_evm::Signature> for SignatureDto {
    /// Convert an EVM signature into its wire view.
    fn from(value: &daemon_wallet_evm::Signature) -> Self {
        let _ = value;
        todo!()
    }
}

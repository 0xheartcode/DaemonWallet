//! Chain-agnostic wallet organisation model, built on the encrypted
//! [`daemon_wallet_vault`] store.
//!
//! This crate owns how a wallet is *organised* and *persisted* without knowing
//! anything about any particular blockchain. It holds the nested group tree,
//! seed and imported-key metadata, accounts, and the manifest that serialises
//! them into the vault. Everything a specific chain must do (derive an address,
//! form a signature, parse an address) is expressed through the narrow
//! [`chain::Chain`] trait and supplied by a sibling crate such as
//! `daemon-wallet-evm`.
//!
//! # The split, made concrete
//!
//! This crate depends on the vault and serde only. It has **no**
//! `alloy-primitives` dependency and no chain-specific code. That is enforced by
//! construction: an account's address is the neutral [`chain::ChainAddress`]
//! string, not any chain's native address type, and signing goes through
//! opaque, chain-tagged [`chain::SigningPayload`]s rather than typed
//! transactions. A new chain family is a new crate implementing [`chain::Chain`]
//! plus a new [`chain::ChainKind`] variant; core itself does not change.
//!
//! # How the pieces fit
//!
//! - A [`Wallet`] is the aggregate. It wraps one vault, one in-memory
//!   [`WalletManifest`], and a [`chain::ChainRegistry`]. The manifest is the
//!   whole organisational picture (group tree, seeds, keys, accounts) and holds
//!   no secret material.
//! - Secret material lives in dedicated vault entries addressed by id (see
//!   [`manifest`]). The manifest only holds the metadata plus the id needed to
//!   fetch the secret back.
//! - Per-account derivation and signing are routed through the
//!   [`chain::ChainRegistry`] to the right [`chain::Chain`].
//!
//! # Security posture
//!
//! Reveal operations ([`Wallet::export_seed`], [`Wallet::export_key`]) require
//! the caller to re-authenticate; the address-only export
//! ([`Wallet::export_public_csv`]) does not, because it discloses no secret.

#![forbid(unsafe_code)]

pub mod account;
pub mod chain;
pub mod error;
pub mod group;
pub mod id;
pub mod key;
pub mod manifest;
pub mod seed;
pub mod wallet;

pub use account::{Account, AccountSource};
pub use chain::{
    AccountSecret, Chain, ChainAddress, ChainKind, ChainRegistry, PayloadKind, SigningPayload,
};
pub use error::{Error, Result};
pub use group::{Group, GroupTree};
pub use id::{AccountId, GroupId, KeyId, SeedId};
pub use key::ImportedKey;
pub use manifest::{MANIFEST_VERSION, WalletManifest};
pub use seed::{DerivationPath, DerivationScheme, SeedSource};
pub use wallet::{ForgetOutcome, RemoveGroupPolicy, Wallet};

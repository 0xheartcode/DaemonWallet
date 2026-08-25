//! Accounts: an address the wallet can sign for, plus how it was obtained.
//!
//! An [`Account`] is the unit a user actually sends from. It is either derived
//! from a [`crate::seed::SeedSource`] at some index or backed by a standalone
//! [`crate::key::ImportedKey`]; [`AccountSource`] records which. The account
//! also records the group it is filed under, so the [`crate::group::GroupTree`]
//! stays a pure folder structure and account membership is a back-reference
//! rather than a list embedded in each group node.
//!
//! An account carries its [`crate::chain::ChainKind`] so the wallet knows which
//! [`crate::chain::Chain`] to route derivation and signing through, and its
//! address is the chain-neutral [`crate::chain::ChainAddress`] rather than any
//! chain-specific address type.

use crate::chain::{ChainAddress, ChainKind};
use crate::id::{AccountId, GroupId, KeyId, SeedId};
use crate::seed::DerivationPath;
use serde::{Deserialize, Serialize};

/// Where an account's signing key comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSource {
    /// Derived from a seed at a fixed index. The `path` is stored explicitly
    /// (rather than recomputed from the seed's scheme on demand) so the account
    /// still resolves even if the seed's scheme is later changed.
    Derived {
        /// The seed this account was derived from.
        seed: SeedId,
        /// The account index used against that seed.
        index: u32,
        /// The fully resolved derivation path.
        path: DerivationPath,
    },
    /// Backed by a standalone imported private key.
    Imported {
        /// The imported key that controls this address.
        key: KeyId,
    },
}

/// One signable address together with its provenance and display state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Stable id.
    pub id: AccountId,
    /// The chain family this account belongs to. Routes derivation and signing
    /// to the correct [`crate::chain::Chain`].
    pub chain: ChainKind,
    /// The chain-neutral address, cached so it can be shown without unlocking
    /// the secret.
    pub address: ChainAddress,
    /// Whether the account is derived or imported.
    pub source: AccountSource,
    /// The group this account is filed under.
    pub group: GroupId,
    /// Human-facing label.
    pub label: String,
    /// When true the account is hidden from normal listings but still fully
    /// functional and, if derived, still re-derivable.
    pub hidden: bool,
    /// When true a derived account is a tombstone: it must never be handed back
    /// out by [`crate::Wallet::derive_next_account`]. This is how "forget" is
    /// expressed for derived accounts, which cannot be truly deleted because
    /// the seed would simply reproduce them. Always `false` for imported
    /// accounts, which are deleted outright instead.
    pub do_not_rederive: bool,
    /// Free-form notes.
    pub notes: String,
    /// Arbitrary user tags.
    pub tags: Vec<String>,
}

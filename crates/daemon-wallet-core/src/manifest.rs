//! The wallet manifest and its mapping onto vault entries.
//!
//! # One manifest entry, many secret entries
//!
//! A [`crate::Wallet`] is persisted across a set of [`daemon_wallet_vault`]
//! entries with a fixed naming scheme:
//!
//! - **The manifest entry**, at the fixed id [`MANIFEST_ENTRY_ID`], holds the
//!   CBOR encoding of a [`WalletManifest`]: the whole [`crate::group::GroupTree`]
//!   plus every [`crate::seed::SeedSource`], [`crate::key::ImportedKey`], and
//!   [`crate::account::Account`]. It contains no secret material, only metadata
//!   and the ids that route to the secrets.
//! - **One secret entry per seed**, at id [`seed_entry_id`]`(seed_id)`, whose
//!   secret bytes are that seed's mnemonic.
//! - **One secret entry per imported key**, at id [`key_entry_id`]`(key_id)`,
//!   whose secret bytes are that key's raw private scalar.
//!
//! So a wallet with two seeds and one imported key occupies exactly four vault
//! entries: `wallet/manifest`, `seed/<id>`, `seed/<id>`, and `key/<id>`.
//!
//! # Why split it this way
//!
//! The vault encrypts every entry's secret bytes but treats an entry's id and
//! [`daemon_wallet_vault::Meta`] as addressing, not secret. Putting the mnemonics
//! and private keys in their own entries keeps each secret independently
//! addressable (fetch exactly the one key a signature needs, nothing more)
//! while the bulky, frequently rewritten organisational state travels as a
//! single blob that is cheap to re-encode on every [`crate::Wallet::save`].
//!
//! # Round-trip
//!
//! - [`crate::Wallet::save`] encodes the manifest with [`WalletManifest::encode`]
//!   and writes it to [`MANIFEST_ENTRY_ID`] via `Vault::put`, then calls
//!   `Vault::save`.
//! - [`crate::Wallet::open`] reads [`MANIFEST_ENTRY_ID`] via `Vault::get` and
//!   decodes it with [`WalletManifest::decode`].
//! - Secret entries are written when a seed or key is added, read when a
//!   signature or export needs them, and removed when an imported key is
//!   forgotten.

use crate::account::Account;
use crate::group::GroupTree;
use crate::id::{AccountId, KeyId, SeedId};
use crate::key::ImportedKey;
use crate::seed::SeedSource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The schema version of the manifest blob, bumped on breaking layout changes.
///
/// [`WalletManifest::decode`] rejects a stored version it does not understand
/// with [`crate::Error::ManifestVersion`], mirroring how the vault refuses a
/// file format from the future.
pub const MANIFEST_VERSION: u16 = 1;

/// The fixed vault entry id under which the CBOR manifest is stored.
pub const MANIFEST_ENTRY_ID: &str = "wallet/manifest";

/// The vault entry id holding the mnemonic for a given seed.
///
/// Deterministic in the seed id, so no separate index is needed to find a
/// seed's secret.
pub fn seed_entry_id(seed: &SeedId) -> String {
    let _ = seed;
    todo!()
}

/// The vault entry id holding the private key for a given imported key.
pub fn key_entry_id(key: &KeyId) -> String {
    let _ = key;
    todo!()
}

/// The full non-secret state of a wallet, serialised as one CBOR blob.
///
/// This is the single source of truth for how the wallet is organised. It is
/// held in memory while the wallet is unlocked and re-encoded into the manifest
/// vault entry on every save. It never contains a mnemonic or private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletManifest {
    /// Schema version of this manifest, checked on decode.
    pub version: u16,
    /// The nested group tree.
    pub tree: GroupTree,
    /// Every seed source, keyed by id.
    pub seeds: BTreeMap<SeedId, SeedSource>,
    /// Every imported key, keyed by id.
    pub keys: BTreeMap<KeyId, ImportedKey>,
    /// Every account, keyed by id.
    pub accounts: BTreeMap<AccountId, Account>,
}

impl WalletManifest {
    /// Build an empty manifest whose tree is a single root group.
    pub fn new(root_group_name: impl Into<String>) -> Self {
        let _ = root_group_name;
        todo!()
    }

    /// Encode the manifest to CBOR for storage in the manifest vault entry.
    ///
    /// Fails with [`crate::Error::ManifestEncode`] on an encoding error.
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        todo!()
    }

    /// Decode a manifest from the CBOR bytes read out of the vault.
    ///
    /// Fails with [`crate::Error::ManifestDecode`] if the bytes are not a valid
    /// manifest, or [`crate::Error::ManifestVersion`] if the stored version is
    /// newer than [`MANIFEST_VERSION`].
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        let _ = bytes;
        todo!()
    }
}

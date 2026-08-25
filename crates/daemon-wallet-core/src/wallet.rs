//! The [`Wallet`] aggregate: one vault, one manifest, one chain registry.
//!
//! [`Wallet`] is the front door of this crate. It owns an open
//! [`daemon_wallet_vault::Vault`], the in-memory [`WalletManifest`] decoded from
//! it, and a [`ChainRegistry`] of the chain implementations it may route to. It
//! is the only type that touches the organisational state and the secret
//! entries at once, and every wallet operation an application performs is a
//! method here.
//!
//! Crucially the wallet is chain-agnostic. It never derives an address or forms
//! a signature itself: for each account it looks up the [`crate::chain::Chain`]
//! for that account's [`ChainKind`] in the registry and delegates. That is what
//! lets this crate carry no chain-specific dependency while still driving real
//! derivation and signing.
//!
//! Mutating operations change only the in-memory manifest (and, for secrets,
//! the vault's entry set); nothing is persisted until [`Wallet::save`] writes
//! the re-encoded manifest and flushes the vault to disk.

use crate::chain::{ChainKind, ChainRegistry, SigningPayload};
use crate::error::Result;
use crate::group::{Group, GroupTree};
use crate::id::{AccountId, GroupId, KeyId, SeedId};
use crate::manifest::WalletManifest;
use crate::seed::DerivationScheme;
use daemon_wallet_vault::{KdfParams, SecretBytes, Vault};
use std::path::PathBuf;

/// What to do with a group's contents when it is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveGroupPolicy {
    /// Refuse the removal if the group still contains child groups or accounts.
    RequireEmpty,
    /// Move the group's child groups and accounts up to its parent, then remove
    /// the now-empty group.
    Reparent,
    /// Recursively remove the whole subtree. Accounts inside follow
    /// [`Wallet::forget_account`] semantics: derived accounts are tombstoned,
    /// imported accounts are deleted and their key material zeroized.
    Cascade,
}

/// The result of [`Wallet::forget_account`], which differs by account kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgetOutcome {
    /// A derived account was tombstoned: hidden and marked do-not-rederive. Its
    /// index remains consumed against the seed, so the seed will never hand the
    /// same account back out. The record is kept precisely so that index cannot
    /// be silently reused.
    Tombstoned,
    /// An imported account was truly deleted: its [`crate::account::Account`]
    /// and [`crate::key::ImportedKey`] were dropped from the manifest and the
    /// private-key vault entry was removed and zeroized. Nothing can reproduce
    /// it.
    Deleted,
}

/// A hierarchical-deterministic, multi-chain wallet persisted through an
/// encrypted vault.
pub struct Wallet {
    /// The open, unlocked vault backing this wallet. Holds the manifest entry
    /// and one secret entry per seed and imported key.
    #[allow(dead_code)]
    vault: Vault,
    /// The decoded organisational state. Rewritten to the vault on `save`.
    #[allow(dead_code)]
    manifest: WalletManifest,
    /// The chain implementations this wallet may route derivation and signing
    /// to, keyed by family. Supplied by the caller at open time.
    #[allow(dead_code)]
    chains: ChainRegistry,
}

impl Wallet {
    /// Create a brand-new, empty wallet at `path`.
    ///
    /// This creates the underlying vault (mirroring
    /// [`daemon_wallet_vault::Vault::create`]) and writes an empty manifest with
    /// a single root group. The caller supplies the [`ChainRegistry`] of chain
    /// implementations the wallet may use; register at least the families it
    /// will hold accounts for.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &[u8],
        keyfile: Option<&[u8]>,
        params: KdfParams,
        chains: ChainRegistry,
    ) -> Result<Self> {
        let _ = (path.into(), password, keyfile, params, chains);
        todo!()
    }

    /// Open an existing wallet at `path`, decoding its manifest.
    ///
    /// Mirrors [`daemon_wallet_vault::Vault::open`] for the password/keyfile
    /// rules, then reads and decodes the manifest entry. The caller supplies the
    /// [`ChainRegistry`], which must cover every family the stored accounts
    /// belong to for signing to succeed later.
    pub fn open(
        path: impl Into<PathBuf>,
        password: &[u8],
        keyfile: Option<&[u8]>,
        chains: ChainRegistry,
    ) -> Result<Self> {
        let _ = (path.into(), password, keyfile, chains);
        todo!()
    }

    /// Re-encode the manifest into its vault entry and flush the vault to disk.
    pub fn save(&mut self) -> Result<()> {
        todo!()
    }

    /// Borrow the full non-secret organisational state.
    pub fn manifest(&self) -> &WalletManifest {
        &self.manifest
    }

    /// Borrow the group tree.
    pub fn tree(&self) -> &GroupTree {
        &self.manifest.tree
    }

    /// Borrow the chain registry this wallet routes through.
    pub fn chains(&self) -> &ChainRegistry {
        &self.chains
    }

    // --- Groups -----------------------------------------------------------

    /// Add a child group under `parent`, returning its new id.
    pub fn add_group(&mut self, parent: &GroupId, name: impl Into<String>) -> Result<GroupId> {
        let _ = (parent, name.into());
        todo!()
    }

    /// Rename a group.
    pub fn rename_group(&mut self, id: &GroupId, name: impl Into<String>) -> Result<()> {
        let _ = (id, name.into());
        todo!()
    }

    /// Move a group (and its whole subtree) under a new parent.
    ///
    /// Fails if `id` is the root or if `new_parent` is inside `id`'s subtree
    /// (see [`GroupTree::move_node`]).
    pub fn move_group(&mut self, id: &GroupId, new_parent: &GroupId) -> Result<()> {
        let _ = (id, new_parent);
        todo!()
    }

    /// Remove a group according to `policy` (see [`RemoveGroupPolicy`]).
    pub fn remove_group(&mut self, id: &GroupId, policy: RemoveGroupPolicy) -> Result<()> {
        let _ = (id, policy);
        todo!()
    }

    /// List every group as a depth-first pre-order walk starting at the root.
    pub fn list_tree(&self) -> Vec<&Group> {
        todo!()
    }

    // --- Seeds and derivation --------------------------------------------

    /// Register a new seed for a chain family from its mnemonic, returning its
    /// id.
    ///
    /// The mnemonic bytes are written to a fresh vault secret entry (see
    /// [`crate::manifest::seed_entry_id`]) and a [`crate::seed::SeedSource`] for
    /// `chain` with `next_index = 0` is added to the manifest. The caller's
    /// `mnemonic` buffer should be zeroized by the caller after this returns.
    /// `notes` and `tags` start empty.
    pub fn add_seed(
        &mut self,
        chain: ChainKind,
        label: impl Into<String>,
        scheme: DerivationScheme,
        passphrase_protected: bool,
        mnemonic: &[u8],
    ) -> Result<SeedId> {
        let _ = (chain, label.into(), scheme, passphrase_protected, mnemonic);
        todo!()
    }

    /// Derive the seed's next account, filed under `group`, advancing the
    /// seed's `next_index` cursor.
    ///
    /// The address is produced by the [`crate::chain::Chain`] registered for the
    /// seed's family. The cursor only moves forward and skips any index already
    /// consumed by a live or tombstoned account, so a forgotten index is never
    /// reissued.
    pub fn derive_next_account(
        &mut self,
        seed: &SeedId,
        group: &GroupId,
        label: impl Into<String>,
    ) -> Result<AccountId> {
        let _ = (seed, group, label.into());
        todo!()
    }

    /// Derive a specific account index from a seed, filed under `group`.
    ///
    /// Does not move the `next_index` cursor unless `index` is at or beyond it.
    /// Fails if that index is already materialised as a live account.
    pub fn derive_account_at(
        &mut self,
        seed: &SeedId,
        index: u32,
        group: &GroupId,
        label: impl Into<String>,
    ) -> Result<AccountId> {
        let _ = (seed, index, group, label.into());
        todo!()
    }

    // --- Imported keys ----------------------------------------------------

    /// Import a standalone private key for a chain family, filed under `group`,
    /// returning the id of the single account it produces.
    ///
    /// The private key is written to a fresh vault secret entry (see
    /// [`crate::manifest::key_entry_id`]); the address is computed by the
    /// [`crate::chain::Chain`] for `chain`, and an [`crate::key::ImportedKey`]
    /// plus one [`crate::account::Account`] with
    /// [`crate::account::AccountSource::Imported`] are added to the manifest.
    /// The caller should zeroize its `private_key` buffer after this returns.
    pub fn import_key(
        &mut self,
        chain: ChainKind,
        label: impl Into<String>,
        private_key: &[u8],
        group: &GroupId,
    ) -> Result<AccountId> {
        let _ = (chain, label.into(), private_key, group);
        todo!()
    }

    // --- Visibility and lifecycle ----------------------------------------

    /// Hide an account from normal listings.
    ///
    /// The account stays fully functional and, if derived, still re-derivable.
    /// Hiding is purely cosmetic and reversible with [`Wallet::unhide_account`].
    pub fn hide_account(&mut self, id: &AccountId) -> Result<()> {
        let _ = id;
        todo!()
    }

    /// Reverse a previous [`Wallet::hide_account`].
    ///
    /// This does not resurrect a forgotten (tombstoned) derived account; only a
    /// merely-hidden one can be un-hidden.
    pub fn unhide_account(&mut self, id: &AccountId) -> Result<()> {
        let _ = id;
        todo!()
    }

    /// Forget an account. Semantics depend on how it was created.
    ///
    /// - **Derived**: the account is *tombstoned* rather than deleted. It is
    ///   hidden and marked do-not-rederive, and its index stays consumed so the
    ///   parent seed will never reproduce it. Returns [`ForgetOutcome::Tombstoned`].
    /// - **Imported**: the account is *truly deleted*. Its
    ///   [`crate::account::Account`] and [`crate::key::ImportedKey`] are removed
    ///   from the manifest and the private-key vault entry is deleted and
    ///   zeroized. Returns [`ForgetOutcome::Deleted`].
    pub fn forget_account(&mut self, id: &AccountId) -> Result<ForgetOutcome> {
        let _ = id;
        todo!()
    }

    // --- Signing ----------------------------------------------------------

    /// Sign a chain-tagged payload with the given account's key, returning the
    /// raw signature bytes the chain produced.
    ///
    /// This is the single, chain-neutral signing entry point. The wallet
    /// resolves the account's secret from the vault (seed material plus path for
    /// a derived account, or the raw private key for an imported one), looks up
    /// the [`crate::chain::Chain`] for the account's family, and delegates. The
    /// payload's [`crate::chain::SigningPayload::chain`] tag must match the
    /// account's family or the call fails with [`crate::Error::ChainMismatch`].
    ///
    /// Chain-specific request builders (an EVM transaction, an EIP-712 document)
    /// live in the chain crates and encode into a
    /// [`crate::chain::SigningPayload`]; interpreting the resulting bytes back
    /// into a typed signature is likewise the chain crate's job.
    pub fn sign(&self, account: &AccountId, payload: &SigningPayload) -> Result<Vec<u8>> {
        let _ = (account, payload);
        todo!()
    }

    // --- Export (gated) ---------------------------------------------------

    /// Reveal a seed's mnemonic. **Gated**: requires re-authentication.
    ///
    /// `reauth` must match the vault password; a mismatch fails with
    /// [`crate::Error::Reauth`] and reveals nothing. This gate is enforced here
    /// rather than left to the caller precisely because the payload is the most
    /// sensitive secret the wallet holds. The client is still expected to layer
    /// its own confirmation UX on top.
    pub fn export_seed(&self, seed: &SeedId, reauth: &[u8]) -> Result<SecretBytes> {
        let _ = (seed, reauth);
        todo!()
    }

    /// Reveal an imported key's private scalar. **Gated**: requires
    /// re-authentication, exactly as [`Wallet::export_seed`].
    pub fn export_key(&self, key: &KeyId, reauth: &[u8]) -> Result<SecretBytes> {
        let _ = (key, reauth);
        todo!()
    }

    /// Export public account data (address, label, derivation path, group) as
    /// CSV. **Not gated**: it discloses no secret, so no re-authentication is
    /// required. Hidden and tombstoned accounts are included, flagged as such.
    pub fn export_public_csv(&self) -> Result<String> {
        todo!()
    }
}

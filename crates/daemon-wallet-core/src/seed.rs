//! Seed sources: metadata for an HD mnemonic whose secret lives in the vault.
//!
//! A [`SeedSource`] is the non-secret half of an HD mnemonic. The phrase itself
//! is never stored here; it lives in a dedicated vault entry addressed by the
//! [`crate::id::SeedId`] (see [`crate::manifest`]). This struct records only
//! what is needed to describe the seed and to derive further accounts from it:
//! a label, the chain family it derives for, the derivation scheme, and a
//! monotonically increasing `next_index` cursor.

use crate::chain::ChainKind;
use crate::id::SeedId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A derivation path such as `m/44'/60'/0'/0/0`.
///
/// Wrapped in a newtype so an account's derivation path cannot be confused with
/// an arbitrary string elsewhere in the domain. The value is the fully resolved
/// path for one account, not a template. Core stores and passes it around but
/// never interprets it; the owning [`crate::chain::Chain`] does.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DerivationPath(String);

impl DerivationPath {
    /// Wrap a fully resolved path string.
    pub fn from_raw(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerivationPath({})", self.0)
    }
}

/// The rule that turns an account index into a concrete [`DerivationPath`].
///
/// Keeping the scheme as data (rather than hard-coding one path shape) lets a
/// single wallet host seeds that follow different conventions, for example a
/// Ledger-style layout alongside the standard MetaMask one. Core owns the
/// templating; the chain decides what a resolved path actually means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DerivationScheme {
    /// Standard BIP-44 Ethereum: `m/44'/60'/0'/0/{index}`. This is what
    /// MetaMask and most software wallets use.
    Bip44Standard,
    /// BIP-44 varying the account field instead of the address index:
    /// `m/44'/60'/{index}'/0/0`. This is the Ledger Live layout.
    Bip44LedgerLive,
    /// A custom template. The literal substring `{index}` is replaced by the
    /// account index at derivation time; everything else is copied verbatim.
    Custom {
        /// A path template containing exactly one `{index}` placeholder.
        template: String,
    },
}

impl DerivationScheme {
    /// Resolve the concrete [`DerivationPath`] for a given account index.
    pub fn path_for(&self, index: u32) -> DerivationPath {
        let _ = index;
        todo!()
    }
}

/// The metadata describing one seed (mnemonic) held by the wallet.
///
/// The mnemonic bytes are not present; fetch them from the vault via the seed's
/// id when a signing or export operation genuinely needs them.
///
/// A seed is bound to a single [`ChainKind`]. Reusing one mnemonic across chain
/// families is modelled as separate [`SeedSource`]s, one per family, so that a
/// seed's derivation scheme, resolved addresses, and `next_index` cursor all
/// belong to exactly one chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedSource {
    /// Stable id; also the routing key to this seed's vault entry.
    pub id: SeedId,
    /// The chain family this seed derives accounts for.
    pub chain: ChainKind,
    /// Human-facing label.
    pub label: String,
    /// Free-form notes.
    pub notes: String,
    /// Arbitrary user tags.
    pub tags: Vec<String>,
    /// Whether a BIP-39 passphrase (the "25th word") guards this mnemonic. The
    /// passphrase, if any, is supplied at unlock/derive time and is never
    /// stored.
    pub passphrase_protected: bool,
    /// The next unused account index. [`crate::Wallet::derive_next_account`]
    /// reads and advances this cursor; it only ever moves forward, so a
    /// forgotten index is never silently handed out again.
    pub next_index: u32,
    /// How account indices map to derivation paths for this seed.
    pub derivation_scheme: DerivationScheme,
}

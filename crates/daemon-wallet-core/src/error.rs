//! Error type for the chain-agnostic wallet core.
//!
//! Vault-level failures are wrapped verbatim so a caller can still distinguish,
//! for example, a wrong password ([`daemon_wallet_vault::Error::Auth`]) from a
//! missing object. As in the vault, no secret material is ever placed in an
//! error message. Chain-specific failures surface here as the neutral
//! [`Error::Derivation`], [`Error::Signing`], or [`Error::AddressParse`]; the
//! concrete chain crate is where the underlying detail lives.

use crate::chain::ChainKind;
use crate::id::{AccountId, GroupId, KeyId, SeedId};
use thiserror::Error;

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by wallet operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A failure originating in the underlying encrypted vault.
    #[error("vault error: {0}")]
    Vault(#[from] daemon_wallet_vault::Error),

    /// No group exists for the given id.
    #[error("group not found")]
    GroupNotFound(GroupId),

    /// No seed source exists for the given id.
    #[error("seed not found")]
    SeedNotFound(SeedId),

    /// No imported key exists for the given id.
    #[error("imported key not found")]
    KeyNotFound(KeyId),

    /// No account exists for the given id.
    #[error("account not found")]
    AccountNotFound(AccountId),

    /// A group move was rejected because it would place a node inside its own
    /// subtree, which would sever that subtree from the root.
    #[error("group move would create a cycle")]
    GroupCycle,

    /// The root group cannot be removed, moved, or reparented.
    #[error("the root group is immutable")]
    RootImmutable,

    /// A group could not be removed because it still holds children or accounts
    /// and the chosen [`crate::wallet::RemoveGroupPolicy`] forbids that.
    #[error("group is not empty")]
    GroupNotEmpty,

    /// The manifest bytes read from the vault could not be decoded.
    #[error("manifest could not be decoded")]
    ManifestDecode,

    /// The in-memory manifest could not be encoded for storage.
    #[error("manifest could not be encoded")]
    ManifestEncode,

    /// The stored manifest schema version is newer than this build understands.
    #[error("unsupported manifest version {0}")]
    ManifestVersion(u16),

    /// A reveal operation was refused because re-authentication did not match
    /// the vault's password.
    #[error("re-authentication failed")]
    Reauth,

    /// No [`crate::chain::Chain`] is registered for the family an operation
    /// needs, so derivation or signing cannot be routed.
    #[error("no chain implementation registered for this family")]
    ChainNotRegistered(ChainKind),

    /// A signing payload's chain tag disagreed with the account's chain family.
    #[error("payload chain does not match the account's chain")]
    ChainMismatch,

    /// A chain implementation could not parse or canonicalise an address.
    #[error("address could not be parsed")]
    AddressParse,

    /// A chain implementation failed to derive an address or signing key.
    #[error("key or address derivation failed")]
    Derivation,

    /// A chain implementation failed to produce a signature.
    #[error("signing failed")]
    Signing,
}

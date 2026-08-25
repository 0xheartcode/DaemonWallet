//! Imported keys: metadata for a standalone private key held in the vault.
//!
//! An [`ImportedKey`] is a private key that was pasted in rather than derived
//! from a seed. As with seeds, the secret scalar never appears here; it lives
//! in a dedicated vault entry addressed by the [`crate::id::KeyId`] (see
//! [`crate::manifest`]). This struct records the public metadata only.

use crate::chain::{ChainAddress, ChainKind};
use crate::id::KeyId;
use serde::{Deserialize, Serialize};

/// The metadata describing one imported private key.
///
/// Exactly one [`crate::account::Account`] is backed by each imported key,
/// because a single key yields exactly one address. The `address` here is
/// cached from that key so the wallet can display and match it without
/// unlocking the secret. It is stored in the chain-neutral [`ChainAddress`]
/// form; the owning chain crate produced it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportedKey {
    /// Stable id; also the routing key to this key's vault entry.
    pub id: KeyId,
    /// The chain family this key controls an address on.
    pub chain: ChainKind,
    /// Human-facing label.
    pub label: String,
    /// Free-form notes.
    pub notes: String,
    /// Arbitrary user tags.
    pub tags: Vec<String>,
    /// The address this key controls, cached from the secret at import time.
    pub address: ChainAddress,
}

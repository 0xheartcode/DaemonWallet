//! The EVM chain-info registry and its safe external-merge interface.
//!
//! This registry is EVM *metadata* (chain id, name, symbol, rpc urls) and is a
//! different thing from core's [`daemon_wallet_core::ChainRegistry`], which
//! dispatches [`daemon_wallet_core::Chain`] implementations by family. To keep
//! the two crisp this one is named [`ChainInfoRegistry`].
//!
//! # This crate validates and stores; it never fetches
//!
//! A rich, up-to-date chain list is useful, but fetching it is a client concern
//! (the CLI or app pulls `https://chainlist.org/rpcs.json` over the network and
//! parses it into `Vec<ChainInfo>`). This crate performs **no** network I/O. Its
//! job is the trust boundary: take externally sourced chain data and decide,
//! safely, what may enter the registry via [`ChainInfoRegistry::merge_validated`].
//!
//! # Why the built-in set is authoritative
//!
//! The registry ships with a small, pinned set of well-known chains (see
//! [`ChainInfoRegistry::builtin`]). Those entries are authoritative: external
//! data can never overwrite them. The reason is replay safety, not tidiness. A
//! chain id is what a signature is bound to; if a hostile or merely wrong
//! chainlist entry could rebind chain id `1` to a different name, symbol, or RPC
//! set, a user could be induced to sign for what they believe is Ethereum
//! mainnet while transacting somewhere else. Pinning the mapping for known ids
//! removes that class of attack. New, unknown chain ids from external data are
//! welcome; rewrites of known ones are refused.
//!
//! # Validation rules enforced on merge
//!
//! 1. **HTTPS only.** Every RPC url must be `https://…`. Non-HTTPS urls are
//!    stripped from an incoming entry; if that leaves the entry with no url it
//!    is dropped.
//! 2. **Known ids are immutable.** An incoming entry whose `chain_id` is in the
//!    authoritative built-in set is rejected wholesale, never merged.
//!
//! The outcome of a merge is a [`MergeReport`]. There is no fallible I/O in a
//! merge, so every per-entry decision is reported as data rather than raised as
//! an error, and the call therefore returns a [`MergeReport`] directly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Static description of one EVM chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    /// The EIP-155 chain id.
    pub chain_id: u64,
    /// Human-facing name, for example `"Ethereum Mainnet"`.
    pub name: String,
    /// The native currency symbol, for example `"ETH"`.
    pub native_symbol: String,
    /// The native currency's decimal places (18 for every current EVM chain,
    /// but stored rather than assumed).
    pub decimals: u8,
    /// Candidate JSON-RPC endpoints. After a validated merge every url here is
    /// guaranteed to be `https://…`.
    pub rpc_urls: Vec<String>,
    /// Optional block explorer base url.
    pub explorer: Option<String>,
}

/// The chain ids that ship pinned and authoritative in every registry.
///
/// These are exactly the ids [`ChainInfoRegistry::merge_validated`] refuses to
/// let external data overwrite.
pub const BUILTIN_CHAIN_IDS: [u64; 7] = [
    1,        // Ethereum Mainnet
    11155111, // Sepolia
    8453,     // Base
    42161,    // Arbitrum One
    10,       // OP Mainnet
    137,      // Polygon
    56,       // BNB Smart Chain
];

/// A lookup of [`ChainInfo`] keyed by chain id.
///
/// Start from [`ChainInfoRegistry::builtin`], then optionally fold in externally
/// fetched chains through [`ChainInfoRegistry::merge_validated`]. Manual, trusted
/// edits go through [`ChainInfoRegistry::insert`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainInfoRegistry {
    /// Every known chain, keyed by id.
    chains: BTreeMap<u64, ChainInfo>,
}

impl ChainInfoRegistry {
    /// Build a registry pre-loaded with the pinned built-in chains (mainnet,
    /// Sepolia, Base, Arbitrum One, OP Mainnet, Polygon, BNB Smart Chain).
    pub fn builtin() -> Self {
        todo!()
    }

    /// Look up a chain by id.
    pub fn get(&self, chain_id: u64) -> Option<&ChainInfo> {
        let _ = chain_id;
        todo!()
    }

    /// Look up a chain by case-insensitive name.
    pub fn by_name(&self, name: &str) -> Option<&ChainInfo> {
        let _ = name;
        todo!()
    }

    /// Insert or replace a chain from a trusted source, returning any entry it
    /// displaced.
    ///
    /// This is the unguarded path for the wallet's own code and manual user
    /// edits. It applies none of the [`ChainInfoRegistry::merge_validated`]
    /// safety rules, so callers must supply data they already trust.
    pub fn insert(&mut self, info: ChainInfo) -> Option<ChainInfo> {
        let _ = info;
        todo!()
    }

    /// Iterate over every chain in id order.
    pub fn iter(&self) -> impl Iterator<Item = &ChainInfo> {
        self.chains.values()
    }

    /// Whether a chain id is part of the authoritative, immutable built-in set.
    pub fn is_authoritative(chain_id: u64) -> bool {
        let _ = chain_id;
        todo!()
    }

    /// Safely fold externally fetched chain data into the registry.
    ///
    /// The `external` vector is the already-parsed content a client fetched from
    /// a source such as `https://chainlist.org/rpcs.json`; this crate does not
    /// fetch it. Each entry is put through the validation rules documented on
    /// this module (HTTPS-only rpc urls, and no overwriting an authoritative
    /// built-in id), and the returned [`MergeReport`] records what happened to
    /// each one.
    pub fn merge_validated(&mut self, external: Vec<ChainInfo>) -> MergeReport {
        let _ = external;
        todo!()
    }
}

/// A per-entry account of what a [`ChainInfoRegistry::merge_validated`] call did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Chain ids newly added to the registry.
    pub inserted: Vec<u64>,
    /// Previously-merged (non-authoritative) chain ids whose entry was updated.
    pub updated: Vec<u64>,
    /// Chain ids refused because they are authoritative built-ins.
    pub rejected_authoritative: Vec<u64>,
    /// Chain ids dropped because no HTTPS rpc url remained after filtering.
    pub rejected_no_secure_rpc: Vec<u64>,
    /// Total count of individual non-HTTPS rpc urls stripped across all entries.
    pub stripped_insecure_urls: usize,
}

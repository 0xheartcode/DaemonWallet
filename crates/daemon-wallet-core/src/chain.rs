//! The narrow chain abstraction that keeps this crate chain-agnostic.
//!
//! Core knows how a wallet is *organised* (groups, seeds, keys, accounts) but
//! nothing about how any particular chain derives an address or shapes a
//! signature. Everything chain-specific is expressed through the [`Chain`]
//! trait and reached through a [`ChainRegistry`]. A [`crate::Wallet`] looks up
//! the [`Chain`] for an account's [`ChainKind`] and delegates derivation and
//! signing to it.
//!
//! # Adding a new chain family without touching core
//!
//! A new chain (say Solana or Bitcoin) is added as a *sibling crate* that
//! depends on this one and implements [`Chain`] for its own type, converting
//! between its native address type and the neutral [`ChainAddress`] at its own
//! boundary. The application then registers an instance into the
//! [`ChainRegistry`] it hands to [`crate::Wallet`]. Core gains a new
//! [`ChainKind`] variant (the enum is `#[non_exhaustive]` precisely so that is
//! a non-breaking change) and nothing else here changes. `daemon-wallet-evm` is
//! exactly this pattern for the EVM family.
//!
//! # Object safety
//!
//! [`Chain`] is deliberately object-safe: no generic methods, no `Self` by
//! value, only `&self` plus concrete argument and return types. That lets the
//! registry store implementations as `Box<dyn Chain>` and dispatch at runtime
//! on [`ChainKind`].

use crate::seed::DerivationPath;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The family of blockchain an account belongs to.
///
/// This is the routing key from an account to its [`Chain`] implementation. It
/// is `#[non_exhaustive]` so that shipping support for a new family is a
/// non-breaking change for downstream code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChainKind {
    /// The EVM family: Ethereum and every EVM-compatible chain. Implemented by
    /// `daemon-wallet-evm`.
    Evm,
}

/// A chain-neutral account address, held in its canonical string form.
///
/// Core never interprets the bytes of an address, so it stores whatever
/// canonical text the owning chain produces: a checksummed `0x…` hex string for
/// EVM, a base58 string for a future Solana chain, and so on. Conversion to and
/// from a chain's native address type happens inside that chain's crate, never
/// here. This is the concrete reason core carries no `alloy-primitives`
/// dependency.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainAddress(String);

impl ChainAddress {
    /// Wrap a canonical address string. The owning chain is responsible for
    /// having canonicalised it first (see [`Chain::parse_address`]).
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the canonical address text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChainAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ChainAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainAddress({})", self.0)
    }
}

/// The secret an account signs with, in whichever form the wallet holds it.
///
/// The wallet resolves one of these from the vault just before a derivation or
/// signature and passes it to the [`Chain`], which alone knows how to turn it
/// into a signing key. Deriving the concrete private key stays inside the chain
/// implementation so the key spends as little time as possible in core.
pub enum AccountSecret<'a> {
    /// HD seed material plus the path to the account's key. The chain performs
    /// the key derivation.
    Derived {
        /// The seed bytes (a decoded mnemonic, for example).
        seed_material: &'a [u8],
        /// The path identifying which key under the seed to use.
        path: &'a DerivationPath,
    },
    /// A raw account private key, as imported.
    Imported {
        /// The private key bytes.
        private_key: &'a [u8],
    },
}

/// What a [`SigningPayload`]'s body is, so the chain interprets it correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PayloadKind {
    /// The body is a ready-made digest to be signed as-is.
    Digest,
    /// The body is a chain-specific transaction encoding.
    Transaction,
    /// The body is an arbitrary message (personal-sign style).
    Message,
    /// The body is a chain-specific typed-data document.
    TypedData,
}

/// A chain-tagged request to produce a signature over opaque bytes.
///
/// Core treats `body` as opaque: it never parses it. The `chain` tag lets the
/// wallet route the payload to the correct [`Chain`], which then interprets
/// `body` according to `kind`. A client crate builds one of these with the
/// right encoding (for EVM, `daemon-wallet-evm` provides the helpers).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningPayload {
    /// Which chain family must interpret and sign this.
    pub chain: ChainKind,
    /// How to interpret `body`.
    pub kind: PayloadKind,
    /// The opaque, chain-specific bytes to sign.
    pub body: Vec<u8>,
}

/// The chain-specific operations that the chain-agnostic core delegates to.
///
/// One implementation exists per chain family, lives in that family's own
/// crate, and is registered into a [`ChainRegistry`]. See the module docs for
/// how a new family plugs in.
pub trait Chain {
    /// The chain family this implementation serves. Used as its registry key.
    fn kind(&self) -> ChainKind;

    /// Derive the account address controlled by `seed_material` at `path`.
    fn derive_address(
        &self,
        seed_material: &[u8],
        path: &DerivationPath,
    ) -> crate::Result<ChainAddress>;

    /// Compute the address controlled by a raw imported private key.
    fn import_address(&self, private_key: &[u8]) -> crate::Result<ChainAddress>;

    /// Sign a chain-tagged [`SigningPayload`] with an account's secret,
    /// returning raw signature bytes whose layout is the chain's own.
    fn sign(&self, secret: AccountSecret<'_>, payload: &SigningPayload) -> crate::Result<Vec<u8>>;

    /// Validate and canonicalise an address string into a [`ChainAddress`].
    fn parse_address(&self, text: &str) -> crate::Result<ChainAddress>;

    /// Render a [`ChainAddress`] in this chain's canonical display form.
    fn format_address(&self, address: &ChainAddress) -> String;
}

/// A dispatch table from [`ChainKind`] to its [`Chain`] implementation.
///
/// The application builds one, registers each chain crate's implementation into
/// it, and hands it to [`crate::Wallet::create`] or [`crate::Wallet::open`].
/// The wallet then routes every per-account derivation and signature through
/// it. Because it holds `Box<dyn Chain>` it is a runtime object and is neither
/// cloned nor serialised.
#[derive(Default)]
pub struct ChainRegistry {
    /// The registered implementations, keyed by the family they serve.
    #[allow(dead_code)]
    chains: BTreeMap<ChainKind, Box<dyn Chain>>,
}

impl ChainRegistry {
    /// An empty registry with no chains registered.
    pub fn new() -> Self {
        Self {
            chains: BTreeMap::new(),
        }
    }

    /// Register an implementation, keyed by its own [`Chain::kind`].
    ///
    /// Returns any implementation it displaced for that family.
    pub fn register(&mut self, chain: Box<dyn Chain>) -> Option<Box<dyn Chain>> {
        let _ = chain;
        todo!()
    }

    /// Borrow the implementation for a family, or `None` if none is registered.
    pub fn get(&self, kind: ChainKind) -> Option<&dyn Chain> {
        let _ = kind;
        todo!()
    }

    /// Whether a family has an implementation registered.
    pub fn contains(&self, kind: ChainKind) -> bool {
        let _ = kind;
        todo!()
    }

    /// The families that currently have an implementation registered.
    pub fn kinds(&self) -> Vec<ChainKind> {
        self.chains.keys().copied().collect()
    }
}

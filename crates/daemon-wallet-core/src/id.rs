//! Stable, opaque identifiers for wallet objects.
//!
//! Every long-lived object (group, seed, imported key, account) is addressed by
//! its own newtype id rather than by array index or by a mutable natural key
//! such as an address. Two properties matter here.
//!
//! - The ids survive reorganisation. Moving an account between groups, hiding
//!   it, or renaming a seed never changes its id, so references from other
//!   objects (an [`crate::account::Account`] pointing at its [`SeedId`]) stay
//!   valid.
//! - The ids double as the routing key into the vault. A [`SeedId`] deterministic
//!   ally maps to the vault entry holding that seed's mnemonic (see
//!   [`crate::manifest`]), so the manifest never has to store a second lookup
//!   table.
//!
//! The inner value is an opaque string. The intended generator is a random
//! UUID rendered as text, but nothing in the contract depends on that: callers
//! must treat the value as an opaque token and compare it only for equality.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Define an opaque string-backed identifier newtype with the shared surface.
///
/// Each generated type is `Clone`, ordered (so it can key a `BTreeMap`),
/// hashable, and serde-serialisable, and exposes the same tiny set of methods.
macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Wrap an already-generated token as a [`", stringify!($name), "`].")]
            ///
            /// The caller owns uniqueness. Prefer [`Self::generate`] for new
            /// objects and reserve this for reloading an id that was persisted
            /// earlier.
            pub fn from_raw(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[doc = concat!("Mint a fresh, unique [`", stringify!($name), "`].")]
            ///
            /// The returned value is prefixed with a short type tag so ids are
            /// self-describing in logs and vault listings.
            pub fn generate() -> Self {
                todo!()
            }

            /// Borrow the opaque token as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The short type tag that new ids of this kind are prefixed with.
            pub const fn prefix() -> &'static str {
                $prefix
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

id_newtype!(
    /// Identifies a node in the [`crate::group::GroupTree`], including the root.
    GroupId,
    "grp"
);
id_newtype!(
    /// Identifies a [`crate::seed::SeedSource`] and, by extension, the vault
    /// entry holding its mnemonic.
    SeedId,
    "seed"
);
id_newtype!(
    /// Identifies an [`crate::key::ImportedKey`] and, by extension, the vault
    /// entry holding its private key.
    KeyId,
    "key"
);
id_newtype!(
    /// Identifies an [`crate::account::Account`].
    AccountId,
    "acct"
);

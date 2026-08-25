//! The nested group tree, modelled as a flat arena.
//!
//! # Why an arena and not a recursive struct
//!
//! The obvious model for an arbitrary-depth tree is a recursive struct such as
//! `struct Group { children: Vec<Group>, .. }`. We deliberately do not use it.
//! Instead the whole forest lives in one flat map, [`GroupTree::nodes`], keyed
//! by [`GroupId`], where each [`Group`] stores its `parent` and its `children`
//! as ids rather than owning the child structs.
//!
//! This buys three things that matter for a wallet.
//!
//! 1. Serialization is trivial and safe. A flat `map<id, node>` round-trips
//!    through CBOR without any recursion, so a pathologically deep tree cannot
//!    blow the stack while (de)serialising, and there is no ownership puzzle to
//!    encode.
//! 2. Moving a subtree is a pointer re-link, not a deep move. Reparenting a
//!    node means editing three vectors (drop from the old parent's `children`,
//!    push onto the new parent's, rewrite the node's `parent`) in place. In a
//!    recursive struct the same operation forces you to lift an owned subtree
//!    out of one `Vec<Group>` and graft it into another, fighting the borrow
//!    checker the whole way.
//! 3. Ids stay stable across every reorganisation, so other objects can
//!    reference a group by id and never dangle.
//!
//! The cost is that the parent/children invariant is maintained by hand in the
//! mutators rather than guaranteed by the shape of the data. All mutation goes
//! through the methods on [`GroupTree`], which are the only place that
//! invariant is enforced.

use crate::id::GroupId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single node in the [`GroupTree`].
///
/// A group is a labelled folder. It carries display metadata (`name`, `notes`,
/// `tags`) and its structural links (`parent`, `children`) as ids. Accounts are
/// not stored inline here; an [`crate::account::Account`] points back at the
/// group it belongs to (see [`crate::account::Account::group`]), so listing a
/// group's accounts is a filter over the account map rather than a field on the
/// node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// This group's own id. The root group's id is [`GroupTree::root`].
    pub id: GroupId,
    /// The parent group's id, or `None` for the root.
    pub parent: Option<GroupId>,
    /// Child group ids, in display order.
    pub children: Vec<GroupId>,
    /// Human-facing name.
    pub name: String,
    /// Free-form notes.
    pub notes: String,
    /// Arbitrary user tags.
    pub tags: Vec<String>,
}

/// An arbitrary-depth tree of [`Group`] nodes held in a flat arena.
///
/// Construct one with [`GroupTree::new`], which seeds the arena with a single
/// root node. Every other node descends from that root. The tree never becomes
/// empty: the root cannot be removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupTree {
    /// The id of the root node, which always exists and has no parent.
    root: GroupId,
    /// The arena: every node in the tree, keyed by id. See the module docs for
    /// why nodes are stored flat rather than nested.
    nodes: BTreeMap<GroupId, Group>,
}

impl GroupTree {
    /// Create a new tree containing only a root group with the given name.
    pub fn new(root_name: impl Into<String>) -> Self {
        let _ = root_name;
        todo!()
    }

    /// The root group's id.
    pub fn root(&self) -> &GroupId {
        &self.root
    }

    /// Borrow a group by id, or `None` if no such node exists.
    pub fn get(&self, id: &GroupId) -> Option<&Group> {
        let _ = id;
        todo!()
    }

    /// Iterate over every group in the tree in id order.
    ///
    /// The order is stable but not structural; use [`GroupTree::children`] or
    /// [`GroupTree::path_to`] when hierarchy matters.
    pub fn iter(&self) -> impl Iterator<Item = &Group> {
        self.nodes.values()
    }

    /// The direct child ids of a group, or `None` if the group is unknown.
    pub fn children(&self, id: &GroupId) -> Option<&[GroupId]> {
        let _ = id;
        todo!()
    }

    /// The chain of ids from the root down to and including `id`.
    ///
    /// Returns `None` if the id is unknown. The first element is always the
    /// root and the last is always `id`.
    pub fn path_to(&self, id: &GroupId) -> Option<Vec<GroupId>> {
        let _ = id;
        todo!()
    }

    /// Add a new child group under `parent` and return its fresh id.
    ///
    /// Fails with [`crate::Error::GroupNotFound`] if `parent` does not exist.
    pub fn add(&mut self, parent: &GroupId, name: impl Into<String>) -> crate::Result<GroupId> {
        let _ = (parent, name.into());
        todo!()
    }

    /// Rename a group in place.
    pub fn rename(&mut self, id: &GroupId, name: impl Into<String>) -> crate::Result<()> {
        let _ = (id, name.into());
        todo!()
    }

    /// Reparent `id` under `new_parent`, re-linking both parents' child lists.
    ///
    /// Fails with [`crate::Error::RootImmutable`] if `id` is the root, and with
    /// [`crate::Error::GroupCycle`] if `new_parent` is `id` itself or any node
    /// in `id`'s own subtree.
    pub fn move_node(&mut self, id: &GroupId, new_parent: &GroupId) -> crate::Result<()> {
        let _ = (id, new_parent);
        todo!()
    }

    /// Remove a leaf group.
    ///
    /// This is the low-level primitive: it only unlinks the node from its
    /// parent and drops it from the arena, and it fails with
    /// [`crate::Error::GroupNotEmpty`] if the node still has children. The
    /// wallet-level [`crate::Wallet::remove_group`] layers account-handling
    /// policy on top of this.
    pub fn remove(&mut self, id: &GroupId) -> crate::Result<Group> {
        let _ = id;
        todo!()
    }
}

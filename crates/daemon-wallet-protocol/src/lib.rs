//! The daemon-wallet plug-in wire contract.
//!
//! This crate is the boundary between the wallet daemon and its clients (a
//! browser extension, a CLI, an app). It defines what may cross the wire and
//! nothing about how the bytes travel; the transport lands in M3. Because it is
//! a contract, the types here are deliberately stable and self-contained:
//! requests and responses are plain serde enums, and every payload is a DTO
//! ([`dto`]) rather than an internal [`daemon_wallet_evm`] domain type, so the
//! domain can evolve without breaking the wire.
//!
//! # Framing
//!
//! Every message is wrapped in a versioned envelope ([`RequestEnvelope`],
//! [`ResponseEnvelope`]) carrying the [`PROTOCOL_VERSION`] it was built against
//! and a [`RequestId`] that correlates a response, or a later approval, back to
//! its request. A peer that receives an envelope whose version it does not
//! support answers with [`Error::UnsupportedVersion`] rather than guessing.
//!
//! # Request lifecycle
//!
//! Some requests (for example [`Request::SignTransaction`]) do not complete
//! inline: the daemon parks them for human approval and returns an
//! [`dto::ApprovalDto`]. The client (or the wallet UI) later resolves them with
//! [`Request::ApproveRequest`] or [`Request::RejectRequest`], keyed by the
//! original [`RequestId`].

#![forbid(unsafe_code)]

pub mod client;
pub mod dto;

pub use dto::{
    AccountDto, AccountRef, AccountSourceKind, ApprovalDto, ApprovalKind, GroupDto, Origin,
    SignatureDto, StatusDto, TxRequestDto, TypedDataDto,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The wire-contract version this build speaks.
///
/// Bumped only on a breaking change to the framing or the request/response
/// shapes. A peer compares it against an incoming envelope's
/// [`RequestEnvelope::protocol_version`] and refuses a mismatch it cannot
/// handle.
pub const PROTOCOL_VERSION: u32 = 1;

/// Correlation id linking a response, and any later approval, to its request.
///
/// The requesting side allocates it and treats it as opaque; the daemon echoes
/// it back and uses it to key parked approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// A request travelling from a client to the daemon.
///
/// The variants differ a lot in size (a bare `Lock` versus a
/// [`Request::SignTransaction`] carrying a whole [`TxRequestDto`]). That spread
/// is inherent to a message enum and harmless here: these values are
/// constructed, serialised, and dropped, never held in large hot collections,
/// so boxing one field to equalise sizes would add indirection for no real
/// gain. The lint is allowed deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Request {
    /// Unlock the wallet. `password` may be omitted when the daemon can unlock
    /// from an OS keychain or an already-cached key.
    Unlock {
        /// The vault password, when the client supplies it directly.
        password: Option<String>,
    },
    /// Lock the wallet, dropping all in-memory secrets.
    Lock,
    /// Ask for daemon status (see [`StatusDto`]).
    Status,
    /// List the group tree.
    ListTree,
    /// List accounts.
    ListAccounts,
    /// Record that an origin (a dapp) wishes to connect.
    Connect {
        /// The requesting origin, for example `https://app.uniswap.org`.
        origin: Origin,
    },
    /// Drop a previously connected origin.
    Disconnect {
        /// The origin to disconnect.
        origin: Origin,
    },
    /// Request a transaction signature. Typically parked for approval.
    SignTransaction {
        /// The account to sign with.
        account: AccountRef,
        /// The transaction to sign.
        tx: TxRequestDto,
        /// The origin making the request.
        origin: Origin,
    },
    /// Request an EIP-712 typed-data signature. Typically parked for approval.
    SignTypedData {
        /// The account to sign with.
        account: AccountRef,
        /// The typed-data payload.
        typed_data: TypedDataDto,
        /// The origin making the request.
        origin: Origin,
    },
    /// Request an EIP-191 `personal_sign`. Typically parked for approval.
    PersonalSign {
        /// The account to sign with.
        account: AccountRef,
        /// The raw message bytes to sign.
        message: alloy_primitives::Bytes,
        /// The origin making the request.
        origin: Origin,
    },
    /// Approve a previously parked request by id.
    ApproveRequest {
        /// The parked request's id.
        id: RequestId,
    },
    /// Reject a previously parked request by id.
    RejectRequest {
        /// The parked request's id.
        id: RequestId,
    },
}

/// A successful response from the daemon.
///
/// Failures are carried out of band as [`Error`] in the
/// [`ResponseEnvelope::result`], not as a variant here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Response {
    /// The wallet is now unlocked.
    Unlocked,
    /// The wallet is now locked.
    Locked,
    /// Current daemon status.
    Status(StatusDto),
    /// The group tree.
    Tree(Vec<GroupDto>),
    /// The account list.
    Accounts(Vec<AccountDto>),
    /// An origin was connected; the accounts it may see are included.
    Connected {
        /// Accounts exposed to the newly connected origin.
        accounts: Vec<AccountDto>,
    },
    /// An origin was disconnected.
    Disconnected,
    /// A request was parked and awaits approval.
    Pending(ApprovalDto),
    /// A signing request completed and produced this signature.
    Signature(SignatureDto),
    /// A parked request was approved.
    Approved,
    /// A parked request was rejected.
    Rejected,
}

/// A request travelling from a client to the daemon, framed for the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestEnvelope {
    /// The [`PROTOCOL_VERSION`] the sender built this against.
    pub protocol_version: u32,
    /// Correlation id for the eventual response.
    pub id: RequestId,
    /// The request payload.
    pub request: Request,
}

/// A response travelling from the daemon back to a client, framed for the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    /// The [`PROTOCOL_VERSION`] the daemon built this against.
    pub protocol_version: u32,
    /// The [`RequestId`] this response corresponds to.
    pub id: RequestId,
    /// The outcome: a [`Response`] on success or an [`Error`] on failure.
    pub result: core::result::Result<Response, Error>,
}

/// A protocol-level error, serialisable so it can travel on the wire.
#[derive(Clone, Debug, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Error {
    /// The peer's [`PROTOCOL_VERSION`] is not one this side can handle.
    #[error("unsupported protocol version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// The version the peer sent.
        got: u32,
        /// The version this side speaks.
        expected: u32,
    },
    /// The wallet is locked and the request needs it unlocked.
    #[error("wallet is locked")]
    Locked,
    /// The origin is not connected and the request requires a connection.
    #[error("origin is not connected")]
    NotConnected,
    /// The user rejected the request.
    #[error("request was rejected")]
    Rejected,
    /// No account matches the supplied [`AccountRef`].
    #[error("unknown account")]
    UnknownAccount,
    /// No parked request matches the supplied [`RequestId`].
    #[error("unknown request id")]
    UnknownRequest,
    /// The request parameters were malformed or inconsistent.
    #[error("invalid request: {0}")]
    InvalidParams(String),
    /// An unexpected internal failure the client cannot act on.
    #[error("internal error")]
    Internal,
}

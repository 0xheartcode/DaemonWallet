//! A thin, typed client over the wire contract.
//!
//! The client turns ergonomic method calls into [`crate::RequestEnvelope`]s,
//! hands them to a [`Transport`], and unwraps the [`crate::ResponseEnvelope`]
//! back into typed results. It owns no transport of its own: the actual moving
//! of bytes (a unix socket, a browser message port, stdio) is M3, so here the
//! transport is only a trait and every call body is left unimplemented.
//!
//! Keeping the client generic over [`Transport`] means the same typed surface
//! serves every future transport without change, and tests can drive it with an
//! in-memory fake.

use crate::dto::{
    AccountDto, AccountRef, GroupDto, Origin, SignatureDto, StatusDto, TxRequestDto, TypedDataDto,
};
use crate::{Error, RequestEnvelope, RequestId, ResponseEnvelope};
use alloy_primitives::Bytes;

/// Result alias for client calls.
type Result<T> = core::result::Result<T, Error>;

/// A synchronous round-trip transport for envelopes.
///
/// One call sends a [`RequestEnvelope`] and returns the matching
/// [`ResponseEnvelope`]. Transport-level failures (a dropped socket, a decode
/// error) are surfaced as [`Error::Internal`] for now; a richer transport error
/// channel is an M3 concern.
pub trait Transport {
    /// Send one request and block until its response arrives.
    fn call(&self, request: RequestEnvelope) -> Result<ResponseEnvelope>;
}

/// A typed client bound to one [`Transport`].
pub struct Client<T: Transport> {
    /// The underlying transport.
    #[allow(dead_code)]
    transport: T,
    /// Monotonic source of the next [`RequestId`].
    #[allow(dead_code)]
    next_id: u64,
}

impl<T: Transport> Client<T> {
    /// Wrap a transport in a typed client.
    pub fn new(transport: T) -> Self {
        let _ = transport;
        todo!()
    }

    /// Unlock the wallet.
    pub fn unlock(&mut self, password: Option<String>) -> Result<()> {
        let _ = password;
        todo!()
    }

    /// Lock the wallet.
    pub fn lock(&mut self) -> Result<()> {
        todo!()
    }

    /// Fetch daemon status.
    pub fn status(&mut self) -> Result<StatusDto> {
        todo!()
    }

    /// List the group tree.
    pub fn list_tree(&mut self) -> Result<Vec<GroupDto>> {
        todo!()
    }

    /// List accounts.
    pub fn list_accounts(&mut self) -> Result<Vec<AccountDto>> {
        todo!()
    }

    /// Connect an origin, returning the accounts it may see.
    pub fn connect(&mut self, origin: Origin) -> Result<Vec<AccountDto>> {
        let _ = origin;
        todo!()
    }

    /// Disconnect an origin.
    pub fn disconnect(&mut self, origin: Origin) -> Result<()> {
        let _ = origin;
        todo!()
    }

    /// Request a transaction signature.
    ///
    /// Returns the [`SignatureDto`] once the request is approved and signed; the
    /// approval round-trip is handled by the daemon and, in an interactive
    /// client, resolved via [`Client::approve`] / [`Client::reject`].
    pub fn sign_transaction(
        &mut self,
        account: AccountRef,
        tx: TxRequestDto,
        origin: Origin,
    ) -> Result<SignatureDto> {
        let _ = (account, tx, origin);
        todo!()
    }

    /// Request an EIP-712 typed-data signature.
    pub fn sign_typed_data(
        &mut self,
        account: AccountRef,
        typed_data: TypedDataDto,
        origin: Origin,
    ) -> Result<SignatureDto> {
        let _ = (account, typed_data, origin);
        todo!()
    }

    /// Request an EIP-191 `personal_sign`.
    pub fn personal_sign(
        &mut self,
        account: AccountRef,
        message: Bytes,
        origin: Origin,
    ) -> Result<SignatureDto> {
        let _ = (account, message, origin);
        todo!()
    }

    /// Approve a parked request by id.
    pub fn approve(&mut self, id: RequestId) -> Result<()> {
        let _ = id;
        todo!()
    }

    /// Reject a parked request by id.
    pub fn reject(&mut self, id: RequestId) -> Result<()> {
        let _ = id;
        todo!()
    }
}

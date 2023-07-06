//! Errors defined across the MPC implementation
use std::fmt::Display;

use quinn::{ConnectError, ConnectionError};

/// An application level error that results from an error deeper in the MPC stack
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcError {
    /// An error on the network
    NetworkError(MpcNetworkError),
    /// An error authenticating an MPC value
    AuthenticationError,
    /// An error resulting from visibility mismatch between two values
    VisibilityError(String),
    /// An error performing an arithmetic operation
    ArithmeticError(String),
}

impl Display for MpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An error on the MPC network during communication
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcNetworkError {
    /// An error sending a value to the counterparty
    SendError(String),
    /// An error receiving a value from the counterparty
    RecvError(String),
    /// An error setting up the underlying connection
    ConnectionSetupError(SetupError),
    /// An error tearing down the underlying connection
    ConnectionTeardownError,
    /// An error emitted when a network operation is performed on a network
    /// that has not yet been `connect`ed
    NetworkUninitialized,
    /// An error serializing a value
    SerializationError(String),
}

impl Display for MpcNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An error setting up the MPC fabric
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// An error connecting to the peer
    ConnectError(ConnectError),
    /// An error with the connection after initial setup
    ConnectionError(ConnectionError),
    /// An error setting up the TLS certificate
    KeygenError,
    /// An error emitted when there is no inbound connection attempt from the suggested peer
    NoIncomingConnection,
    /// An error setting up the QUIC server on the local node
    ServerSetupError,
}

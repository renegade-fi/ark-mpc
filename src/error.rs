//! Errors defined across the MPC implementation
use quinn::{ConnectError, ConnectionError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcError {
    NetworkError(MpcNetworkError),
    AuthenticationError,
    VisibilityError(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcNetworkError {
    SendError,
    RecvError,
    ConnectionSetupError(SetupError),
    ConnectionTeardownError,
    NetworkUninitialized,
    BroadcastError(BroadcastError),
    SerializationError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    ConnectError(ConnectError),
    ConnectionError(ConnectionError),
    KeygenError,
    NoIncomingConnection,
    ServerSetupError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastError {
    TooFewBytes,
}

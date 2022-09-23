//! Errors defined across the MPC implementation
use quinn::{ConnectionError, ConnectError};

#[derive(Debug)]
pub enum MpcError {
    NetworkError(MpcNetworkError),
    AuthenticationError,
}

#[derive(Debug)]
pub enum MpcNetworkError {
    SendError,
    RecvError,
    ConnectionSetupError(SetupError),
    ConnectionTeardownError,
    NetworkUninitialized,
    BroadcastError(BroadcastError),
    SerializationError,
}

#[derive(Debug)]
pub enum SetupError {
    ConnectError(ConnectError),
    ConnectionError(ConnectionError),
    KeygenError,
    NoIncomingConnection,
    ServerSetupError,
}

#[derive(Debug)]
pub enum BroadcastError {
    TooFewBytes
}


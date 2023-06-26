//! Errors defined across the MPC implementation
use std::fmt::Display;

use quinn::{ConnectError, ConnectionError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcError {
    NetworkError(MpcNetworkError),
    AuthenticationError,
    VisibilityError(String),
    ArithmeticError(String),
}

impl Display for MpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MpcNetworkError {
    SendError(String),
    RecvError,
    ConnectionSetupError(SetupError),
    ConnectionTeardownError,
    NetworkUninitialized,
    BroadcastError(BroadcastError),
    SerializationError(String),
}

impl Display for MpcNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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

//! Errors defined across the MPC implementation
pub enum MPCNetworkError {
    SendError,
    RecvError,
    ConnectionSetupError,
    ConnectionTeardownError,
    NetworkUninitialized,
    BroadcastError(BroadcastError),
    SerializationError,
}

pub enum BroadcastError {
    TooFewBytes
}


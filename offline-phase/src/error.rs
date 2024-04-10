//! Error types for the offline phase
use std::{error::Error, fmt::Display};

/// The error types for the offline phase
#[derive(Clone, Debug)]
pub enum LowGearError {
    /// Error exchanging keys
    KeyExchange(String),
    /// The lowgear setup params requested before setup
    NotSetup,
    /// An error while sending a message
    SendMessage(String),
    /// Received an unexpected message
    UnexpectedMessage(String),
}

impl Display for LowGearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LowGearError::KeyExchange(e) => write!(f, "Key exchange error: {e}"),
            LowGearError::NotSetup => write!(f, "LowGear not setup"),
            LowGearError::SendMessage(e) => write!(f, "Error sending message: {e}"),
            LowGearError::UnexpectedMessage(e) => write!(f, "Unexpected message: {e}"),
        }
    }
}
impl Error for LowGearError {}
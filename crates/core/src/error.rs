use thiserror::Error;

/// A specialized Result type for Hermes operations.
pub type Result<T> = std::result::Result<T, HermesError>;

/// Represents all possible errors that can occur within the Hermes client.
#[derive(Debug, Error)]
pub enum HermesError {
    #[error("Iroh network error: {0}")]
    Iroh(#[from] anyhow::Error),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization/Deserialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Substrate node error: {0}")]
    Subxt(#[source] Box<subxt::Error>),

    #[error("Local Storage/Database error: {0}")]
    Database(#[from] sled::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Identity resolution error: {0}")]
    Identity(String),

    #[error("Payload error: {0}")]
    Payload(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Not yet implemented: {0}")]
    Unimplemented(String),

    #[error("SSRF blocked: {0}")]
    Ssrf(String),

    #[error("Invalid SS58 address: {0}")]
    InvalidSs58(String),
}

impl From<subxt::Error> for HermesError {
    fn from(err: subxt::Error) -> Self {
        HermesError::Subxt(Box::new(err))
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SteganoError {
    #[error("Capacity exceeded: need {needed} bits, cover text provides {available} bits")]
    CapacityExceeded { needed: usize, available: usize },

    #[error("Encoding failed at method '{method}': {reason}")]
    EncodingFailed { method: String, reason: String },

    #[error("Decoding failed at method '{method}': {reason}")]
    DecodingFailed { method: String, reason: String },

    #[error("No steganographic content detected")]
    NothingDetected,

    #[error("Channel collision: carriers '{first}' and '{second}' both use codepoint U+{codepoint:04X}")]
    ChannelCollision {
        first: String,
        second: String,
        codepoint: u32,
    },

    #[error("Composition order: carrier '{carrier}' rewrites visible text and must run last, but '{successor}' follows it")]
    CompositionOrder { carrier: String, successor: String },

    #[error("Integrity check failed: data may be corrupted or wrong method")]
    IntegrityFailed,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: wrong password or corrupted data")]
    DecryptionFailed,

    #[error("Invalid license: {0}")]
    InvalidLicense(String),

    #[error("License expired")]
    LicenseExpired,

    #[error("Module '{module}' not authorized by license")]
    ModuleNotLicensed { module: String },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SteganoError>;

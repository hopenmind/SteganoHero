//! # SteganoHero Core
//!
//! Advanced text steganography library.
//!
//! Three orthogonal capabilities:
//! - **Steganography**: hide data inside cover text (fragile, invisible)
//! - **Watermarking**: mark text for ownership tracing (robust, survives transforms)
//! - **Noise injection**: perturb AI detectors (semi-robust)
//!
//! ## Quick start
//!
//! ```rust
//! use stegano_core::stego::ZeroWidth;
//! use stegano_core::traits::StegoMethod;
//!
//! let zw = ZeroWidth::new();
//! let cover = "A sufficiently long cover text with enough room for bits to be hidden inside";
//! let secret = b"Hello!";
//!
//! let stego = zw.encode(cover, secret).unwrap();
//! let decoded = zw.decode(&stego).unwrap();
//! assert_eq!(decoded, secret);
//! ```

pub mod error;
pub mod traits;

pub mod stego;
pub mod crypto;
pub mod format;
pub mod metrics;
pub mod pipeline;
pub mod signing;
pub mod license;
pub mod forensic;
/// Does a marked document look like its cover. Invariant 4b.
pub mod fidelity;
/// Signed provenance claims over a document, additive layer. SPEC_PROVENANCE.md.
pub mod provenance;
/// Document sovereignty: inspect and clean the marks your own document carries. AR-1.
pub mod sovereignty;
/// C2PA read and verify: the file side of the AI-regulation tool. AR-2.
pub mod c2pa_read;

pub mod utils;

// Future modules
mod noise;
pub mod watermark;

// Re-exports for convenience
pub use error::{Result, SteganoError};
pub use traits::{
    CryptoMethod, DecodeResult, DetectResult, EncodeResult, NoiseMetrics, StegoMethod,
};

//! Agent-facing integration surface for SteganoHero.
//!
//! This crate is a typed adapter over `stegano-core`. It holds no business
//! logic of its own: every command validates its arguments, calls the core,
//! and reports what the core returned. When the core refuses, the refusal is
//! passed on with its reason attached. Nothing is guessed, nothing is
//! substituted, nothing plausible is returned in place of a real answer.
//!
//! Two transports expose the same catalogue:
//!
//! - [`channel`], a JSON-RPC 2.0 channel over standard input and output, used
//!   by the `stegano-mcp` binary;
//! - the REST surface in `stegano-server`, which builds its routes from
//!   [`tools::tool_names`] and dispatches through the same [`tools::call`].
//!
//! Because both transports call one dispatcher, a command answers identically
//! whichever way it is reached. That identity is a property of the wiring, not
//! a claim maintained by hand.
//!
//! ## Naming rules that apply to every string in this crate
//!
//! Every description, label and error message written here names what a
//! command does, never how it does it. The identifiers accepted as parameters
//! come from the core registry and are opaque handles as far as this surface
//! is concerned: the surface passes them through, and never explains them.
//!
//! ## Secrets
//!
//! Secrets, passcodes and private key material are parameters. They are never
//! written to any log, never echoed into an error message, and never returned
//! by a command that was not explicitly asked for them. [`channel`] logs a
//! method name and an outcome, never a payload.

pub mod catalogue;
pub mod channel;
pub mod jsonrpc;
pub mod settings;
pub mod tools;

/// Protocol version this surface implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol versions this surface accepts from a client.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] =
    ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Name reported to a connecting client.
pub const SERVER_NAME: &str = "stegano-hero";

/// Version reported to a connecting client.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

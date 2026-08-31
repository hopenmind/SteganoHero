//! The `stegano-mcp` binary.
//!
//! It takes no arguments and needs no configuration. An assisting agent is
//! pointed at it by name and nothing else:
//!
//! ```json
//! { "mcpServers": { "stegano-hero": { "command": "stegano-mcp" } } }
//! ```
//!
//! Settings, when a deployment keeps any, are read from the path in the
//! `STEGANO_SETTINGS` environment variable, and from `stegano-settings.json`
//! beside the working directory when that variable is not set. A missing file
//! is not an error: the surface starts from its documented defaults and says
//! so on standard error.

use std::io::{self, BufReader};

use stegano_mcp::channel;
use stegano_mcp::tools::SettingsStore;

fn main() {
    let path = std::env::var("STEGANO_SETTINGS")
        .unwrap_or_else(|_| "stegano-settings.json".to_string());

    let mut store = match SettingsStore::at(&path) {
        Ok(store) => store,
        Err(reason) => {
            // Settings that exist but cannot be read are a real fault: starting
            // on the defaults instead would run under settings the operator
            // did not choose and would never be told about.
            eprintln!("settings at {path} could not be read: {reason}");
            std::process::exit(2);
        }
    };

    eprintln!(
        "{} {} ready, {} commands available, settings from {}",
        stegano_mcp::SERVER_NAME,
        stegano_mcp::SERVER_VERSION,
        stegano_mcp::tools::tool_names().len(),
        if std::path::Path::new(&path).exists() {
            path.as_str()
        } else {
            "defaults"
        }
    );

    let input = BufReader::new(io::stdin());
    if let Err(e) = channel::serve(input, io::stdout(), io::stderr(), &mut store) {
        eprintln!("the channel stopped: {e}");
        std::process::exit(1);
    }
}

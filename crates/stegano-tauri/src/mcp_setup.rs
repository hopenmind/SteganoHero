//! One-click MCP client setup.
//!
//! The desktop app can point common assistant clients at the bundled
//! `stegano-mcp` stdio server. Two honesty rules shape this module:
//!
//! - It only WRITES to a client whose config format is a single, stable JSON file
//!   with a `mcpServers` object (Claude Desktop, Cursor, Windsurf). It merges the
//!   one entry into the existing file, backs the file up first, and refuses to
//!   touch a file it cannot parse, so a client's own settings are never lost.
//! - For a client whose format it cannot write safely (a command-driven or TOML
//!   or workspace-scoped config), it hands back the exact snippet to paste rather
//!   than guessing a format and corrupting the file. What is certain is done; what
//!   is not is shown.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value};

/// The name the server is registered under in every client.
const SERVER_KEY: &str = "stegano-hero";

/// How a client stores its MCP servers, which decides whether this module writes
/// the config or only shows the snippet.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// A single JSON file with a top-level `mcpServers` object. Written directly.
    JsonMcpServers,
    /// Configured by a CLI command; the command is shown, not a file written.
    Command,
    /// A TOML config; the snippet is shown rather than a TOML merge attempted.
    Toml,
    /// A workspace-scoped or otherwise non-single-path JSON; snippet shown.
    JsonSnippet,
}

/// One client target, resolved for this machine.
#[derive(Debug, Clone, Serialize)]
pub struct McpClient {
    pub id: String,
    pub label: String,
    pub kind: ClientKind,
    /// The resolved config path for a writable client, or the location hint for a
    /// snippet client. Empty when the platform has no known path.
    pub config_path: String,
    /// True when this module can write the config safely on this machine.
    pub writable: bool,
    /// True when the client looks present (its config file or directory exists).
    pub detected: bool,
    /// For a snippet client, the exact text to paste or run. Empty for writables.
    pub snippet: String,
}

/// The full setup picture handed to the interface.
#[derive(Debug, Clone, Serialize)]
pub struct McpSetupInfo {
    /// The resolved `stegano-mcp` command a client launches.
    pub server_command: String,
    /// True when the command resolved to a binary beside this app, false when it
    /// fell back to the bare name (the user must have it on their PATH).
    pub bundled: bool,
    /// The universal JSON snippet, for any client that reads `mcpServers`.
    pub json_snippet: String,
    /// The base URL of the REST surface, for clients that speak HTTP instead.
    pub rest_base_url: String,
    /// Every known client, resolved for this machine.
    pub clients: Vec<McpClient>,
}

/// The result of trying to configure one client.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigureOutcome {
    pub id: String,
    pub label: String,
    /// "configured", "already_present", "snippet", "skipped_not_detected", or
    /// "error". A machine-readable status the interface maps to a message.
    pub status: String,
    /// The config path written, or the snippet to paste, or an error detail.
    pub detail: String,
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn appdata_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

/// Resolve the `stegano-mcp` command a client should launch: the binary beside
/// this app if it is there, otherwise the bare name on the assumption it is on the
/// PATH. The boolean reports which, so the interface can tell the user.
fn resolve_server_command() -> (String, bool) {
    let binary = if cfg!(windows) { "stegano-mcp.exe" } else { "stegano-mcp" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(binary);
            if candidate.is_file() {
                return (candidate.to_string_lossy().into_owned(), true);
            }
        }
    }
    (binary.trim_end_matches(".exe").to_string(), false)
}

/// The path a client keeps its config at on this platform, when there is a single
/// well-known one.
fn claude_desktop_path() -> Option<PathBuf> {
    if cfg!(windows) {
        appdata_dir().map(|d| d.join("Claude").join("claude_desktop_config.json"))
    } else if cfg!(target_os = "macos") {
        home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json")
        })
    } else {
        home_dir().map(|h| h.join(".config").join("Claude").join("claude_desktop_config.json"))
    }
}

fn cursor_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".cursor").join("mcp.json"))
}

fn windsurf_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".codeium").join("windsurf").join("mcp_config.json"))
}

/// True when a config file or its parent directory exists, a good-enough sign the
/// client is installed.
fn looks_present(path: &Path) -> bool {
    path.exists() || path.parent().map(|p| p.exists()).unwrap_or(false)
}

/// The JSON snippet any `mcpServers` client accepts.
pub fn json_snippet(command: &str) -> String {
    let value = json!({
        "mcpServers": {
            SERVER_KEY: { "command": command }
        }
    });
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

/// Build the full client list for this machine, given the resolved command.
fn build_clients(command: &str) -> Vec<McpClient> {
    let mut clients = Vec::new();

    // Writable: a single JSON file with mcpServers.
    for (id, label, path) in [
        ("claude-desktop", "Claude Desktop", claude_desktop_path()),
        ("cursor", "Cursor", cursor_path()),
        ("windsurf", "Windsurf", windsurf_path()),
    ] {
        let config_path = path.clone().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let detected = path.as_deref().map(looks_present).unwrap_or(false);
        clients.push(McpClient {
            id: id.to_string(),
            label: label.to_string(),
            kind: ClientKind::JsonMcpServers,
            config_path,
            writable: true,
            detected,
            snippet: String::new(),
        });
    }

    // Snippet-only: a command, a TOML file, or a workspace-scoped config. The exact
    // text is shown rather than a format guessed and written.
    let claude_code_cmd = format!("claude mcp add-json {SERVER_KEY} '{{\"command\":\"{command}\"}}'");
    clients.push(McpClient {
        id: "claude-code".to_string(),
        label: "Claude Code".to_string(),
        kind: ClientKind::Command,
        config_path: "run this command".to_string(),
        writable: false,
        detected: home_dir().map(|h| h.join(".claude.json").exists()).unwrap_or(false),
        snippet: claude_code_cmd,
    });

    let codex_toml = format!("[mcp_servers.{SERVER_KEY}]\ncommand = \"{command}\"\nargs = []");
    clients.push(McpClient {
        id: "codex".to_string(),
        label: "Codex".to_string(),
        kind: ClientKind::Toml,
        config_path: home_dir()
            .map(|h| h.join(".codex").join("config.toml").to_string_lossy().into_owned())
            .unwrap_or_default(),
        writable: false,
        detected: home_dir().map(|h| h.join(".codex").exists()).unwrap_or(false),
        snippet: codex_toml,
    });

    let vscode_snippet = serde_json::to_string_pretty(&json!({
        "servers": { SERVER_KEY: { "type": "stdio", "command": command, "args": [] } }
    }))
    .unwrap_or_default();
    clients.push(McpClient {
        id: "vscode".to_string(),
        label: "VS Code".to_string(),
        kind: ClientKind::JsonSnippet,
        config_path: ".vscode/mcp.json".to_string(),
        writable: false,
        detected: false,
        snippet: vscode_snippet,
    });

    // Clients whose config format is not verified here get the universal snippet,
    // labelled so the user knows to confirm the format themselves.
    for (id, label) in [("windsurf-next", "Windsurf Next"), ("hermes2", "Hermes2"), ("openclaw", "OpenClaw")] {
        clients.push(McpClient {
            id: id.to_string(),
            label: label.to_string(),
            kind: ClientKind::JsonSnippet,
            config_path: "see the client's MCP docs".to_string(),
            writable: false,
            detected: false,
            snippet: json_snippet(command),
        });
    }

    clients
}

/// The resolved `stegano-mcp` command, for a caller that configures a client.
pub fn server_command() -> String {
    resolve_server_command().0
}

/// The full setup picture for the interface.
pub fn setup_info(rest_base_url: &str) -> McpSetupInfo {
    let (command, bundled) = resolve_server_command();
    McpSetupInfo {
        server_command: command.clone(),
        bundled,
        json_snippet: json_snippet(&command),
        rest_base_url: rest_base_url.to_string(),
        clients: build_clients(&command),
    }
}

/// Merge the `stegano-hero` server into an existing `mcpServers` JSON document,
/// preserving every other key. Returns the merged text and whether the entry was
/// already present and unchanged. Refuses a file that is not a JSON object.
fn merge_mcp_servers(existing: &str, command: &str) -> Result<(String, bool), String> {
    let mut root: Value = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("the existing config is not valid JSON, left untouched: {e}"))?
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "the existing config is not a JSON object, left untouched".to_string())?;

    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| "the config's mcpServers is not an object, left untouched".to_string())?;

    let entry = json!({ "command": command });
    let already = servers.get(SERVER_KEY) == Some(&entry);
    servers.insert(SERVER_KEY.to_string(), entry);

    let text = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not serialise the merged config: {e}"))?;
    Ok((text, already))
}

/// Configure one writable client by merging the entry into its config file, after
/// backing the file up. A snippet client returns its snippet as a "snippet"
/// outcome. A client that is not detected is skipped rather than creating config
/// for software that is not installed.
pub fn configure_client(id: &str, command: &str) -> ConfigureOutcome {
    let clients = build_clients(command);
    let Some(client) = clients.into_iter().find(|c| c.id == id) else {
        return ConfigureOutcome {
            id: id.to_string(),
            label: id.to_string(),
            status: "error".to_string(),
            detail: "unknown client".to_string(),
        };
    };

    if !client.writable {
        return ConfigureOutcome {
            id: client.id,
            label: client.label,
            status: "snippet".to_string(),
            detail: client.snippet,
        };
    }
    if !client.detected {
        return ConfigureOutcome {
            id: client.id,
            label: client.label,
            status: "skipped_not_detected".to_string(),
            detail: client.config_path,
        };
    }

    let path = PathBuf::from(&client.config_path);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let (merged, already) = match merge_mcp_servers(&existing, command) {
        Ok(result) => result,
        Err(reason) => {
            return ConfigureOutcome {
                id: client.id,
                label: client.label,
                status: "error".to_string(),
                detail: reason,
            }
        }
    };

    if already {
        return ConfigureOutcome {
            id: client.id,
            label: client.label,
            status: "already_present".to_string(),
            detail: client.config_path,
        };
    }

    // Back up an existing file before writing, so the change is reversible.
    if path.exists() {
        let backup = path.with_extension("json.stegano.bak");
        if let Err(e) = std::fs::copy(&path, &backup) {
            return ConfigureOutcome {
                id: client.id,
                label: client.label,
                status: "error".to_string(),
                detail: format!("could not back up the existing config: {e}"),
            };
        }
    } else if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return ConfigureOutcome {
                id: client.id,
                label: client.label,
                status: "error".to_string(),
                detail: format!("could not create the config directory: {e}"),
            };
        }
    }

    match std::fs::write(&path, merged) {
        Ok(()) => ConfigureOutcome {
            id: client.id,
            label: client.label,
            status: "configured".to_string(),
            detail: client.config_path,
        },
        Err(e) => ConfigureOutcome {
            id: client.id,
            label: client.label,
            status: "error".to_string(),
            detail: format!("could not write the config: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snippet_registers_the_server_under_its_key() {
        let snippet = json_snippet("stegano-mcp");
        assert!(snippet.contains(SERVER_KEY), "the snippet names the server");
        assert!(snippet.contains("\"command\""), "the snippet gives a command");
        let parsed: Value = serde_json::from_str(&snippet).unwrap();
        assert_eq!(parsed["mcpServers"][SERVER_KEY]["command"], json!("stegano-mcp"));
    }

    #[test]
    fn merge_preserves_other_servers_and_keys() {
        let existing = r#"{ "theme": "dark", "mcpServers": { "other": { "command": "x" } } }"#;
        let (merged, already) = merge_mcp_servers(existing, "stegano-mcp").unwrap();
        assert!(!already, "the entry was newly added");
        let parsed: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed["theme"], json!("dark"), "an unrelated key survives");
        assert_eq!(parsed["mcpServers"]["other"]["command"], json!("x"), "another server survives");
        assert_eq!(parsed["mcpServers"][SERVER_KEY]["command"], json!("stegano-mcp"), "ours is added");
    }

    #[test]
    fn merge_into_an_empty_file_creates_the_structure() {
        let (merged, already) = merge_mcp_servers("", "stegano-mcp").unwrap();
        assert!(!already);
        let parsed: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed["mcpServers"][SERVER_KEY]["command"], json!("stegano-mcp"));
    }

    #[test]
    fn merge_reports_an_unchanged_entry_as_already_present() {
        let existing = r#"{ "mcpServers": { "stegano-hero": { "command": "stegano-mcp" } } }"#;
        let (_merged, already) = merge_mcp_servers(existing, "stegano-mcp").unwrap();
        assert!(already, "an identical entry is reported as already present, so no rewrite");
    }

    #[test]
    fn merge_refuses_a_non_json_file_rather_than_clobbering_it() {
        let err = merge_mcp_servers("this is not json {", "stegano-mcp").unwrap_err();
        assert!(err.contains("not valid JSON"), "a malformed config is left untouched: {err}");
    }

    #[test]
    fn the_client_list_marks_the_writable_and_snippet_clients() {
        let clients = build_clients("stegano-mcp");
        let writable: Vec<&str> = clients.iter().filter(|c| c.writable).map(|c| c.id.as_str()).collect();
        assert!(writable.contains(&"claude-desktop"), "claude desktop is writable");
        assert!(writable.contains(&"cursor"), "cursor is writable");
        assert!(writable.contains(&"windsurf"), "windsurf is writable");
        // The uncertain-format clients are present but not written, only shown.
        let codex = clients.iter().find(|c| c.id == "codex").unwrap();
        assert!(!codex.writable, "codex is snippet-only");
        assert!(clients.iter().any(|c| c.id == "openclaw"), "openclaw is listed");
    }

    #[test]
    fn a_snippet_client_returns_its_snippet_not_a_write() {
        let outcome = configure_client("codex", "stegano-mcp");
        assert_eq!(outcome.status, "snippet", "a snippet client is not written");
        assert!(outcome.detail.contains("stegano-mcp"), "the snippet carries the command");
    }

    #[test]
    fn an_unknown_client_is_an_error() {
        let outcome = configure_client("nope", "stegano-mcp");
        assert_eq!(outcome.status, "error");
    }
}

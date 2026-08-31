#!/usr/bin/env bash
#
# Register the SteganoHero MCP server with common assistant clients on macOS and
# Linux. Merges a single "stegano-hero" entry into each detected client's config,
# backing the file up first and never overwriting it. A client whose config is not
# a plain mcpServers JSON file is left for you to configure by hand, with the exact
# snippet printed at the end.
#
# Requires python3 (for a safe JSON merge). Run:
#   ./configure-mcp.sh [path-to-stegano-mcp]
#
# The argument is the stegano-mcp command a client launches; it defaults to
# "stegano-mcp" on your PATH.

set -euo pipefail

BINARY="${1:-stegano-mcp}"
SERVER_KEY="stegano-hero"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for this installer. Use the app's Rest/mcp tab instead." >&2
  exit 1
fi

merge() {
  local name="$1" path="$2"
  local dir
  dir="$(dirname "$path")"
  if [ ! -d "$dir" ]; then
    printf '%-16s: %s\n' "$name" "skipped (not installed)"
    return
  fi
  [ -f "$path" ] && cp "$path" "$path.stegano.bak"
  local result
  result="$(python3 - "$path" "$BINARY" "$SERVER_KEY" <<'PY'
import json, os, sys
path, binary, key = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as handle:
            cfg = json.load(handle)
    except Exception:
        print("error (existing config is not valid JSON, left untouched)")
        sys.exit(0)
if not isinstance(cfg, dict):
    print("error (existing config is not a JSON object, left untouched)")
    sys.exit(0)
cfg.setdefault("mcpServers", {})[key] = {"command": binary}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(cfg, handle, indent=2)
print("configured -> " + path)
PY
)"
  printf '%-16s: %s\n' "$name" "$result"
}

case "$(uname -s)" in
  Darwin) CLAUDE="$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
  *) CLAUDE="$HOME/.config/Claude/claude_desktop_config.json" ;;
esac

echo "Configuring MCP clients with server '$BINARY'..."
merge "Claude Desktop" "$CLAUDE"
merge "Cursor" "$HOME/.cursor/mcp.json"
merge "Windsurf" "$HOME/.codeium/windsurf/mcp_config.json"

echo
echo "For any other client (Claude Code, Codex, VS Code, and the rest), paste:"
python3 - "$BINARY" "$SERVER_KEY" <<'PY'
import json, sys
print(json.dumps({"mcpServers": {sys.argv[2]: {"command": sys.argv[1]}}}, indent=2))
PY
echo
echo "Claude Code, from a terminal, also accepts:"
echo "  claude mcp add-json $SERVER_KEY '{\"command\":\"$BINARY\"}'"

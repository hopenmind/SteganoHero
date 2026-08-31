<#
.SYNOPSIS
  Register the SteganoHero MCP server with common assistant clients on Windows.

.DESCRIPTION
  Merges a single "stegano-hero" entry into each detected client's config,
  backing the file up first and never overwriting it. A client whose config is
  not a plain mcpServers JSON file is left for you to configure by hand, with the
  exact snippet printed at the end.

  Requires PowerShell 7 (pwsh). Run:
    pwsh ./configure-mcp.ps1 [-Binary <path-to-stegano-mcp>]

.PARAMETER Binary
  The stegano-mcp command a client launches. Defaults to "stegano-mcp" on PATH;
  pass a full path if the binary is not on your PATH.
#>
param([string]$Binary = "stegano-mcp")

$ErrorActionPreference = "Stop"
$ServerKey = "stegano-hero"

function Set-McpEntry {
    param([string]$Name, [string]$Path)

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        return "skipped (not installed)"
    }
    $config = [ordered]@{}
    if (Test-Path $Path) {
        Copy-Item $Path "$Path.stegano.bak" -Force
        try {
            $config = Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            return "error (existing config is not valid JSON, left untouched)"
        }
    }
    if (-not $config.ContainsKey("mcpServers")) {
        $config["mcpServers"] = @{}
    }
    $config["mcpServers"][$ServerKey] = @{ command = $Binary }
    $config | ConvertTo-Json -Depth 20 | Set-Content $Path -Encoding UTF8
    return "configured -> $Path"
}

$targets = [ordered]@{
    "Claude Desktop" = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
    "Cursor"         = Join-Path $env:USERPROFILE ".cursor\mcp.json"
    "Windsurf"       = Join-Path $env:USERPROFILE ".codeium\windsurf\mcp_config.json"
}

Write-Host "Configuring MCP clients with server '$Binary'..." -ForegroundColor Cyan
foreach ($name in $targets.Keys) {
    "{0,-16}: {1}" -f $name, (Set-McpEntry -Name $name -Path $targets[$name]) | Write-Host
}

Write-Host ""
Write-Host "For any other client (Claude Code, Codex, VS Code, and the rest), paste:" -ForegroundColor Cyan
@{ mcpServers = @{ $ServerKey = @{ command = $Binary } } } | ConvertTo-Json -Depth 20 | Write-Host
Write-Host ""
Write-Host "Claude Code, from a terminal, also accepts:" -ForegroundColor Cyan
Write-Host "  claude mcp add-json $ServerKey '{""command"":""$Binary""}'"

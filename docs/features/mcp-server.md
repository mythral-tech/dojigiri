# MCP Server

Dojigiri exposes itself as a [Model Context Protocol](https://modelcontextprotocol.io/) server, allowing AI agents and IDEs to invoke scans programmatically.

## Setup

### Claude Code

Add to your MCP config:

```json
{
  "mcpServers": {
    "dojigiri": {
      "command": "python",
      "args": ["-m", "dojigiri.mcp_server"]
    }
  }
}
```

### Requirements

```bash
pip install dojigiri[mcp]
```

## Available tools

| Tool | Description |
|------|-------------|
| `doji_scan` | Scan files/directories for bugs, security issues, and code quality problems |
| `doji_scan_file` | Quick single-file scan |
| `doji_fix` | Show available auto-fixes for a file (preview only) |
| `doji_sca` | Dependency vulnerability scan |
| `doji_explain` | Plain-language walkthrough of a file |
| `doji_debug` | Debug-focused analysis of a specific file |

All tools are read-only -- they analyze but never modify files.

## Available resources

| Resource URI | Description |
|-------------|-------------|
| `dojigiri://rules` | Full rule catalog with severities and categories |
| `dojigiri://languages` | Supported languages and analysis tiers |
| `dojigiri://config` | Current project configuration |
| `dojigiri://rules/{language}` | Rules for a specific language |

## Available prompts

| Prompt | Description |
|--------|-------------|
| `security_review` | Guided security review of a codebase |
| `code_quality` | Code quality assessment prompt |

## Example usage from an AI agent

The MCP server returns findings in AI-friendly plain text (no ANSI codes), making it easy for agents to parse and act on results.

```
Agent: "Scan src/ for security issues"
→ calls doji_scan(path="src/", min_severity="warning")
→ receives structured findings
→ can then call doji_fix() to get fix suggestions
```

# Dojigiri Security Scanner

VS Code extension for [Dojigiri](https://github.com/mythral-tech/dojigiri) -- real-time security vulnerability scanning for Python, JavaScript, TypeScript, Go, and Rust.

## Features

- Inline diagnostics on save (CRITICAL -> Error, WARNING -> Warning, INFO -> Information)
- Quick fix suggestions inserted as comments above flagged lines
- Status bar with finding count
- Debounced on-type scanning (off by default)
- Workspace-wide scanning with progress

## Install

Dojigiri must be installed:

```bash
pip install dojigiri
```

Then install the extension from VSIX or marketplace.

## Configuration

| Setting | Default | Description |
|---|---|---|
| `dojigiri.path` | `"dojigiri"` | Path to the dojigiri executable or module name |
| `dojigiri.minSeverity` | `"warning"` | Minimum severity: `critical`, `warning`, or `info` |
| `dojigiri.runOnSave` | `true` | Scan automatically on file save |
| `dojigiri.runOnType` | `false` | Scan as you type (1.5s debounce) |

## Commands

- **Dojigiri: Scan Current File** -- scan the active editor file
- **Dojigiri: Scan Workspace** -- scan all supported files with progress

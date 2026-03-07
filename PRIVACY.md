# Dojigiri — Privacy & Data Handling

## What data does Dojigiri collect?

Dojigiri is a static analysis tool. Its behavior depends on the mode you use.

### Static scan (`doji scan .`)

**No data leaves your machine.** All analysis runs locally using regex pattern matching and tree-sitter AST parsing. No network requests are made.

### Deep scan (`doji scan . --deep`)

**Source code is sent to a third-party LLM API.** When you use `--deep`, `debug`, `optimize`, or `explain --deep` commands, Dojigiri sends code chunks to the configured LLM backend for AI-powered analysis.

- **Default backend:** Anthropic (Claude API) at `https://api.anthropic.com`
- **OpenAI-compatible backends:** If you configure `--backend openai` with a `--base-url`, your code is sent to that provider. You are responsible for understanding that provider's data handling policies.
- **What is sent:** Source code chunks, file paths, static analysis findings for context
- **What is NOT sent:** Git history, credentials, environment variables, or files outside the scan scope
- **Retention:** Governed by your LLM provider's data policy. See [Anthropic's privacy policy](https://www.anthropic.com/privacy) for the default backend. Anthropic's API does not use submitted data for training.

You must explicitly opt in to remote analysis via `--accept-remote` or interactive confirmation. Dojigiri will never send code to an external API without your consent.

### Local LLM backends

If you configure a local backend (e.g., Ollama via `DOJI_LLM_BACKEND=openai` with a local `DOJI_LLM_BASE_URL`), no data leaves your machine even in deep scan mode.

### Scan reports

Scan results are stored locally in `~/.dojigiri/reports/` as JSON files. These may contain file paths, code snippets, and finding details from your scanned code. These files are not transmitted anywhere.

## API keys

Dojigiri reads API keys from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). **Do not store API keys in `.doji.toml`** — config files in your project directory may be committed to version control.

## MCP server

When running as an MCP server, Dojigiri restricts file access to the current working directory by default. The server does not transmit data externally unless LLM-powered tools are explicitly invoked.

## Privacy flag

Run `doji privacy` or `doji scan --help` to see this information from the CLI.

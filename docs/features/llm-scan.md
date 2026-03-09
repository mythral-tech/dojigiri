# LLM Deep Scan

Tier 3 analysis. The static engine runs first, then an LLM analyzes what rules missed -- grounded in real dataflow from the semantic layer.

## How it works

1. Tiers 1 and 2 run normally (regex + AST/semantic)
2. Static findings are used to build *focused prompts* -- the LLM gets pointed at suspicious areas rather than reading entire files blind
3. Large files are chunked to fit context windows
4. LLM responses are parsed via structured tool-use schemas with 4-layer recovery
5. Results merge with static findings, tagged `[llm]` so you always know the source

## What it catches that static can't

- Logic bugs requiring business context understanding
- Subtle authentication/authorization flaws
- Complex race conditions
- Data validation gaps across function boundaries
- Security issues in unusual patterns that don't match any rule

## Usage

```bash
export ANTHROPIC_API_KEY=sk-ant-...
doji scan . --deep --accept-remote
```

The `--accept-remote` flag acknowledges that code will be sent to an LLM API.

## Supported backends

| Backend | Model | Setup |
|---------|-------|-------|
| Anthropic | Claude | `ANTHROPIC_API_KEY` |
| OpenAI | GPT-4 | `OPENAI_API_KEY` |
| Ollama | Local models | `--llm-backend ollama` |

## Cost estimates

Deep scan costs depend on codebase size. Rough estimates per scan:

| Project size | Files | Estimated cost |
|-------------|-------|---------------|
| Small (< 50 files) | ~20 scanned | $0.05 - $0.20 |
| Medium (50-200 files) | ~80 scanned | $0.20 - $1.00 |
| Large (200+ files) | ~200 scanned | $1.00 - $5.00 |

Only files with static findings or high-risk patterns are sent to the LLM. Clean files are skipped.

## API key setup

=== "Environment variable"

    ```bash
    export ANTHROPIC_API_KEY=sk-ant-...
    ```

=== ".doji.toml"

    ```toml
    [dojigiri.llm]
    backend = "anthropic"
    model = "claude-sonnet-4-20250514"
    ```

!!! warning
    Never commit API keys. Use environment variables or a secrets manager.

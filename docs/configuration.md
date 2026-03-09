# Configuration

Dojigiri works with zero config. All settings are optional.

## .doji.toml

Place a `.doji.toml` file in your project root:

```toml
[dojigiri]
# Minimum severity to report: "info", "warning", "critical"
min_severity = "warning"

# Rules to suppress globally
ignore_rules = ["todo-marker", "console-log"]

# Parallel workers for file scanning
workers = 8
```

## Ignore patterns

### .doji-ignore

Gitignore-style file exclusion:

```
*.log
vendor/
node_modules/
dist/
*.min.js
```

### Inline suppression

Suppress a specific rule on a single line:

```python
x = eval(user_input)  # doji:ignore(dangerous-eval)
```

## Severity filtering

```bash
doji scan . --min-severity warning    # Skip INFO findings
doji scan . --min-severity critical   # Only critical issues
```

Or in `.doji.toml`:

```toml
[dojigiri]
min_severity = "warning"
```

## Custom rules

Define project-specific regex rules:

```toml
[[dojigiri.rules]]
name = "no-print-statements"
pattern = "\\bprint\\("
severity = "info"
category = "style"
message = "Remove print statements before committing"
languages = ["python"]
```

## Compliance profiles

Built-in presets for common compliance frameworks:

```bash
doji scan . --profile owasp    # OWASP-focused rules
doji scan . --profile dod      # DoD/NIST-focused rules
doji scan . --profile ci       # Lean CI profile (fast, low noise)
```

## LLM configuration

```toml
[dojigiri.llm]
backend = "anthropic"          # anthropic, openai, ollama
model = "claude-sonnet-4-20250514"  # Model to use
```

API keys are read from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). Never put keys in config files.

## Language filtering

```bash
doji scan . --language python     # Only scan Python files
doji scan . --language javascript # Only scan JS files
```

## Output formats

```bash
doji scan . --output text    # Terminal (default)
doji scan . --output json    # Machine-readable
doji scan . --output sarif   # GitHub Code Scanning / SARIF tools
doji scan . --output html    # Self-contained HTML report
```

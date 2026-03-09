# Installation

## pip (recommended)

```bash
pip install dojigiri
```

This installs the core scanner with tree-sitter semantic analysis. No external dependencies beyond Python 3.10+.

### Optional extras

```bash
pip install dojigiri[llm]    # LLM deep scan (Anthropic SDK)
pip install dojigiri[mcp]    # MCP server mode
pip install dojigiri[all]    # Everything
```

### Development install

```bash
pip install dojigiri[dev]    # Adds pytest, hypothesis, coverage
```

## From source

```bash
git clone https://github.com/Inklling/dojigiri
cd dojigiri
pip install -e ".[dev]"
```

## Standalone binary (Nuitka)

Pre-built binaries are compiled via Nuitka (Python &rarr; C &rarr; native). No Python installation needed.

```bash
# Download from GitHub Releases
chmod +x doji
./doji scan .
```

## Homebrew (planned)

```bash
# Coming soon
brew install dojigiri
```

## Verify installation

```bash
doji --version
doji scan --help
```

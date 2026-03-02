# Wiz

Python static analysis + LLM-powered code audit tool.

## Features

- 🔍 **Static Analysis** - 50+ regex rules + Python AST checks across 5+ languages
- 🤖 **LLM Integration** - Optional Claude AI analysis for deeper insights
- ⚡ **Fast** - Parallel scanning (3-4x faster on large repos)
- 💾 **Smart Caching** - Skip unchanged files automatically
- 📊 **Multiple Output Formats** - Console ANSI or JSON
- 🎯 **Language Support** - Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, and more

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd Genesis

# Install dependencies
pip install -r requirements.txt

# Optional: Install anthropic for LLM features
pip install anthropic
```

## Quick Start

### Basic Usage

```bash
# Quick scan (static analysis only - free, instant)
python -m wiz scan .

# Scan specific directory
python -m wiz scan ./src

# Scan with language filter
python -m wiz scan . --lang python

# Deep scan (includes LLM analysis - requires API key)
export ANTHROPIC_API_KEY="your-key-here"
python -m wiz scan . --deep
```

### CLI Commands

```bash
# Scan commands
python -m wiz scan <path>              # Quick scan
python -m wiz scan <path> --deep       # Deep scan with LLM
python -m wiz scan <path> --no-cache   # Disable file caching
python -m wiz scan <path> --workers 8  # Control parallelism (default: 4)

# Filter results
python -m wiz scan . --ignore todo-marker,console-log
python -m wiz scan . --min-severity warning
python -m wiz scan . --min-confidence medium

# Output formats
python -m wiz scan . --output json                # JSON for CI/CD
python -m wiz scan . --output sarif > report.sarif  # SARIF for GitHub Code Scanning

# Baseline/diff mode (CI/CD)
python -m wiz scan . --baseline latest           # Compare against latest report
python -m wiz scan . --baseline path/to/baseline.json  # Compare against specific report

# Debug specific file
python -m wiz debug <file>
python -m wiz debug <file> --error "error message"

# Optimize file
python -m wiz optimize <file>

# View reports
python -m wiz report                   # Show latest scan
python -m wiz cost <path>              # Estimate deep scan cost
python -m wiz setup                    # Check environment
```

## Configuration

### .wiz.toml

Create a `.wiz.toml` file in your project root for persistent project-level settings:

```toml
# Filter settings
ignore_rules = ["todo-marker", "console-log"]
min_severity = "warning"      # low, medium, high, critical
min_confidence = "medium"     # low, medium, high

# Performance
workers = 8                   # Parallel scanning workers (default: 4)
```

CLI arguments override config file settings.

### .wizignore

Create a `.wizignore` file in your project root to exclude files:

```
*.log
test_*.py
node_modules/
*.tmp
```

### Environment Variables

- `ANTHROPIC_API_KEY` - Required for deep scans and LLM features

## What Wiz Detects

### Security Issues
- Hardcoded secrets and API keys
- SQL injection vulnerabilities
- XSS risks (innerHTML, eval, document.write)
- Unsafe deserialization (pickle, yaml.load)
- Path traversal vulnerabilities
- Weak cryptography (MD5, SHA1)
- Shell injection risks

### Code Quality
- **Python**: Unused imports, bare except, mutable defaults, type() comparisons, shadowed builtins
- **JavaScript**: var usage, loose equality (==), console.log leftovers
- **Go**: Unchecked errors, fmt.Print in production
- **Rust**: .unwrap() and .expect() panics, unsafe blocks

### Performance & Style
- High cyclomatic complexity
- Too many function arguments
- Dead/unreachable code
- TODO/FIXME markers
- Long lines (>200 chars)

## CI/CD Integration

Baseline/diff mode is essential for CI/CD pipelines - it shows only new findings compared to a baseline, preventing noise from pre-existing issues.

### GitHub Actions Example

```yaml
name: Security Scan

on: [pull_request]

jobs:
  wiz-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Wiz
        run: |
          pip install -r requirements.txt
      
      - name: Run security scan
        run: |
          python -m wiz scan . --baseline latest --min-severity warning --output sarif > results.sarif
      
      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      
      - name: Check for new issues
        run: |
          # Fail if any new critical/high severity issues found
          if [ $(jq '.summary.critical + .summary.high' results.json) -gt 0 ]; then
            echo "New security issues detected!"
            exit 1
          fi
```

### How Baseline/Diff Works

1. **First scan**: Creates baseline report in `~/.wiz/reports/`
2. **Subsequent scans**: Use `--baseline latest` to compare against most recent report
3. **Matching**: Uses 5-line bucket signatures (file, line_bucket, rule) to identify findings - tolerates minor line shifts without losing track
4. **Result**: Only shows findings not present in baseline

### Local Development Workflow

```bash
# 1. Establish baseline on main branch
git checkout main
python -m wiz scan .

# 2. Switch to feature branch
git checkout feature-branch

# 3. Scan for new issues only
python -m wiz scan . --baseline latest

# Only new findings introduced in feature-branch are shown
```

## Output Examples

### Console Output

```
Quick scanning /project ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Files scanned: 42
Total findings: 23

  Critical: 3
  Warnings: 15
  Info: 5

Critical Issues:
  src/app.py:45 - Hardcoded API key detected
  src/db.py:78 - SQL injection risk in query
```

### JSON Output

```bash
python -m wiz scan . --output json > report.json
```

### SARIF Output

SARIF (Static Analysis Results Interchange Format) is the standard format for GitHub Code Scanning:

```bash
# Generate SARIF report
python -m wiz scan . --output sarif > results.sarif

# Upload to GitHub using CLI
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -F sarif=@results.sarif \
  -F ref=refs/heads/main \
  -F commit_sha=$(git rev-parse HEAD)
```

## Performance

Wiz uses parallel processing by default for 3-4x speedup on multi-core systems:

- **Small repos** (<10 files): ~instant
- **Medium repos** (50-100 files): ~2-3 seconds
- **Large repos** (500+ files): ~5-10 seconds

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests -v

# Run with coverage
pytest tests --cov=wiz --cov-report=html
```

### Project Structure

```
Genesis/
├── wiz/                    # Main package
│   ├── __main__.py        # CLI entry point
│   ├── analyzer.py        # Scan orchestration
│   ├── detector.py        # Static analysis engine
│   ├── languages.py       # Pattern rules (50+ rules)
│   ├── chunker.py         # File splitting for LLM
│   ├── llm.py             # Claude API integration
│   ├── storage.py         # Caching & reports
│   ├── report.py          # Output formatting
│   └── config.py          # Data structures
├── tests/                 # Test suite (120+ tests)
└── README.md             # This file
```

## Version History

### v0.3.0 (Current)
- ✅ Baseline/diff mode for CI/CD (`--baseline` flag)
- ✅ Config file support (`.wiz.toml`)
- ✅ SARIF output format for GitHub Code Scanning
- ✅ Configurable parallelism (`--workers` flag)
- ✅ Confidence filtering (`--min-confidence` flag)
- ✅ Block comment support (Python, JS, Go, etc.)
- ✅ 181 comprehensive tests (up from 120)
- ✅ Detection accuracy improvements
- ✅ LLM retry logic with exponential backoff
- ✅ Static-before-LLM pipeline (partial results survive)
- ✅ Improved JSON recovery and error handling
- ✅ .wizignore support for self-referential findings

### v0.2.0
- Comprehensive test suite (120 tests)
- Fixed yaml-unsafe regex bug
- Refactored AST checks for maintainability
- Added parallel scanning (3-4x speedup)
- CLI improvements (--ignore, --min-severity, --output json)
- .wizignore support
- Auto-prune old reports (keep 50 max)

## Roadmap

- [ ] Deep scan caching (respect file hash cache)
- [ ] Parallel deep scanning
- [ ] Custom rule definitions
- [ ] Auto-fix capabilities
- [ ] VSCode extension

## License

[Add your license here]

## Contributing

[Add contribution guidelines]

## Support

For issues, questions, or contributions, please [add contact info or issue tracker].

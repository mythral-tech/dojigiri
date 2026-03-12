# CI/CD Integration

## GitHub Actions (composite action)

The recommended approach -- reference the action directly:

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: mythral-tech/dojigiri@main
        id: scan
        with:
          min-severity: warning
          output-format: sarif
          fail-on-findings: 'true'

      - name: Results
        if: always()
        run: |
          echo "Findings: ${{ steps.scan.outputs.findings-count }}"
          echo "Critical: ${{ steps.scan.outputs.critical-count }}"
```

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `min-severity` | `warning` | `info`, `warning`, or `critical` |
| `output-format` | `text` | `text`, `json`, or `sarif` |
| `fail-on-findings` | `true` | Fail workflow if findings exist |
| `deep` | `false` | LLM deep scan (needs `ANTHROPIC_API_KEY`) |
| `diff-only` | `false` | Only scan changed files (PR mode) |
| `profile` | | Compliance profile: `owasp`, `dod`, `ci` |
| `ignore-rules` | | Comma-separated rules to suppress |

### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings at or above min-severity |
| `critical-count` | Critical findings only |
| `sarif-path` | Path to SARIF file (when `output-format: sarif`) |

## GitHub Actions (pip install)

If you prefer manual control:

```yaml
name: Security Scan
on: [pull_request]
jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install dojigiri
      - run: doji scan . --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## GitLab CI

```yaml
dojigiri:
  image: python:3.12-slim
  stage: test
  script:
    - pip install dojigiri
    - doji scan . --min-severity warning --output text
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### SARIF output for GitLab SAST

```yaml
dojigiri-sast:
  image: python:3.12-slim
  stage: test
  script:
    - pip install dojigiri
    - doji scan . --output sarif > gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

## Pre-commit hook

```bash
doji hook install     # Install git pre-commit hook
doji hook uninstall   # Remove it
```

The hook runs `doji scan --diff --min-severity warning` on staged files before each commit.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no critical findings |
| `1` | Scan error (bad args, missing path) |
| `2` | Critical security findings detected |

## PR diff scanning

Reduce noise on pull requests by scanning only changed files:

```yaml
jobs:
  pr-scan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: mythral-tech/dojigiri@main
        with:
          diff-only: 'true'
          min-severity: info
          fail-on-findings: 'false'
```

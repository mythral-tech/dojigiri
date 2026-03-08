# Dojigiri GitHub Action

Static security analysis with CWE/NIST compliance mapping for your CI pipeline.

## Basic Usage

```yaml
- uses: inklling/dojigiri-action@v1
  with:
    min-severity: warning
    fail-on-critical: true
```

## PR-Only Scanning

Scan only changed files in pull requests — fast and focused:

```yaml
name: Security Scan
on: pull_request

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: inklling/dojigiri-action@v1
        with:
          diff-only: true
          min-severity: info
          fail-on-critical: true
```

## SARIF Upload to GitHub Code Scanning

Results automatically upload to GitHub's Security tab when using SARIF format (the default):

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: inklling/dojigiri-action@v1
        id: doji
        with:
          output-format: sarif
          fail-on-critical: true
```

Findings appear under the **Security** tab > **Code scanning alerts** in your repository.

## Custom Severity Thresholds

```yaml
- uses: inklling/dojigiri-action@v1
  with:
    min-severity: info          # Show everything (info, warning, critical)
    fail-on-critical: false     # Don't fail the build on critical findings
```

## Compliance Profiles

Use built-in compliance profiles for OWASP, DoD, or CI presets:

```yaml
- uses: inklling/dojigiri-action@v1
  with:
    profile: owasp
    fail-on-critical: true
```

## Ignoring Specific Rules

```yaml
- uses: inklling/dojigiri-action@v1
  with:
    ignore-rules: 'todo-marker,long-line'
```

## Scanning a Subdirectory

```yaml
- uses: inklling/dojigiri-action@v1
  with:
    path: 'src/'
    min-severity: warning
```

## Full Example with Job Summary

```yaml
name: Security
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: inklling/dojigiri-action@v1
        id: doji
        with:
          min-severity: warning
          fail-on-critical: true

      - name: Post summary
        if: always()
        run: |
          echo "### Security Scan" >> "$GITHUB_STEP_SUMMARY"
          echo "- Findings: ${{ steps.doji.outputs.findings-count }}" >> "$GITHUB_STEP_SUMMARY"
          echo "- Critical: ${{ steps.doji.outputs.critical-count }}" >> "$GITHUB_STEP_SUMMARY"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `min-severity` | `warning` | Minimum severity: `info`, `warning`, `critical` |
| `output-format` | `sarif` | Output format: `text`, `json`, `sarif` |
| `fail-on-critical` | `true` | Fail the action on critical findings |
| `diff-only` | `false` | Only scan changed files (PR mode) |
| `profile` | | Compliance profile: `owasp`, `dod`, `ci` |
| `ignore-rules` | | Comma-separated rules to suppress |
| `python-version` | `3.12` | Python version to use |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `sarif-file` | Path to SARIF output file (when using sarif format) |

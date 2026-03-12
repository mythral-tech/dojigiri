# CI Integration

## GitHub Actions

### Composite Action (recommended)

Reference the action directly from your workflow:

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

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `min-severity` | `warning` | Minimum severity: `info`, `warning`, `critical` |
| `output-format` | `text` | Output: `text`, `json`, `sarif` |
| `fail-on-findings` | `true` | Fail the workflow if findings exist |
| `deep` | `false` | LLM-powered deep scan (needs `ANTHROPIC_API_KEY`) |
| `diff-only` | `false` | Only scan changed files (PR mode) |
| `profile` | | Compliance profile: `owasp`, `dod`, `ci` |
| `ignore-rules` | | Comma-separated rules to suppress |
| `python-version` | `3.12` | Python version |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings at or above min-severity |
| `critical-count` | Critical findings only |
| `sarif-path` | Path to SARIF file (when `output-format: sarif`) |

### Reusable Workflow

For organizations that want a shared scan configuration:

```yaml
name: Security
on: [push, pull_request]

jobs:
  scan:
    uses: mythral-tech/dojigiri/.github/workflows/doji-scan.yml@main
    with:
      min-severity: warning
      output-format: sarif
      fail-on-findings: true
    secrets:
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

The reusable workflow handles Python setup, dojigiri installation, SARIF upload, and job summaries automatically.

### PR Diff Scanning

Scan only changed files on pull requests to reduce noise:

```yaml
jobs:
  full-scan:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mythral-tech/dojigiri@main
        with:
          fail-on-findings: 'true'

  pr-scan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: mythral-tech/dojigiri@main
        with:
          diff-only: 'true'
          min-severity: info
          fail-on-findings: 'false'
```

### SARIF Upload (GitHub Advanced Security)

When `output-format` is `sarif`, the action automatically uploads results to GitHub Code Scanning via `github/codeql-action/upload-sarif`. This requires:

- `security-events: write` permission on the job
- GitHub Advanced Security enabled on the repo (free for public repos)

Results appear in the **Security** tab under **Code scanning alerts**.

To upload SARIF manually (e.g., from a custom step):

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dojigiri-results.sarif
    category: dojigiri
```

---

## GitLab CI

```yaml
dojigiri:
  image: python:3.12-slim
  stage: test
  script:
    - pip install --quiet "dojigiri @ git+https://github.com/mythral-tech/dojigiri.git@main"
    - doji scan . --min-severity warning --output text
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# SARIF output for GitLab SAST integration
dojigiri-sast:
  image: python:3.12-slim
  stage: test
  script:
    - pip install --quiet "dojigiri @ git+https://github.com/mythral-tech/dojigiri.git@main"
    - doji scan . --min-severity warning --output sarif > gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Generic CI (pip)

Works anywhere Python 3.10+ is available:

```bash
pip install "dojigiri @ git+https://github.com/mythral-tech/dojigiri.git@main"

# Quick scan, fail on critical (exit code 2)
doji scan . --min-severity warning
EXIT=$?
if [ "$EXIT" = "2" ]; then
  echo "Critical issues found"
  exit 1
fi

# JSON output for programmatic use
doji scan . --output json > results.json

# SARIF output
doji scan . --output sarif > results.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no critical findings |
| `1` | Scan error (bad args, missing path, etc.) |
| `2` | Critical security findings detected |

---

## Docker

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir "dojigiri @ git+https://github.com/mythral-tech/dojigiri.git@main"
ENTRYPOINT ["doji"]
```

```bash
docker build -t dojigiri .
docker run --rm -v "$(pwd):/code" dojigiri scan /code --min-severity warning
```

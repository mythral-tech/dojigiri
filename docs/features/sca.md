# SCA Scanning

Software Composition Analysis -- scan your dependencies for known vulnerabilities.

## Usage

```bash
doji sca .
```

Recursively finds lockfiles in the target directory and checks all dependencies against the [Google OSV](https://osv.dev/) vulnerability database.

## Supported lockfiles

| Ecosystem | Lockfile |
|-----------|----------|
| Python | `requirements.txt` |
| Python | `Pipfile.lock` |
| Python | `poetry.lock` |
| JavaScript | `package-lock.json` |
| JavaScript | `yarn.lock` |
| JavaScript | `pnpm-lock.yaml` |
| Ruby | `Gemfile.lock` |
| Go | `go.sum` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |

## How it works

1. Parses lockfiles to extract package names and pinned versions
2. Queries the Google OSV API for known vulnerabilities
3. Reports CVE IDs, severity scores, and affected version ranges
4. Output available in text, JSON, and SARIF formats

## Example output

```
requirements.txt:
  requests 2.28.0  CVE-2023-32681  MODERATE
    Unintended leak of Proxy-Authorization header

  cryptography 39.0.0  CVE-2023-38325  HIGH
    NULL pointer dereference in PKCS7 parsing

Found 2 vulnerable dependencies in 1 lockfile
```

## CI integration

SCA results are included in SARIF output, so they appear alongside SAST findings in GitHub Code Scanning:

```bash
doji sca . --output sarif > sca-results.sarif
```

#!/usr/bin/env python3
"""Collect Semgrep CE findings on benchmark repos for annotation."""
import json
import os
import subprocess
from pathlib import Path

REPOS = {
    "keycloak": ["services/src", "server-spi/src", "server-spi-private/src", "core/src"],
    "paperless-ngx": ["src"],
    "saleor": ["saleor"],
}

REPOS_DIR = Path(__file__).parent / ".repos"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

for repo, paths in REPOS.items():
    repo_dir = REPOS_DIR / repo
    scan_paths = [str(repo_dir / p) for p in paths if (repo_dir / p).exists()]
    if not scan_paths:
        print(f"{repo}: not cloned, skipping")
        continue

    cmd = [
        "semgrep", "scan", "--config", "auto", "--json", "--quiet",
        "--timeout", "30", "--max-memory", "2048",
    ] + scan_paths

    print(f"{repo}: scanning...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        data = json.loads(result.stdout)
    except Exception as e:
        print(f"  error: {e}")
        continue

    results = data.get("results", [])
    output = []
    for r in results:
        path = r.get("path", "")
        try:
            rel = str(Path(path).relative_to(repo_dir)).replace("\\", "/")
        except (ValueError, TypeError):
            rel = path
        meta = r.get("extra", {}).get("metadata", {})
        output.append({
            "file": rel,
            "line": r.get("start", {}).get("line", 0),
            "rule": r.get("check_id", "").split(".")[-1],
            "full_rule": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "message": r.get("extra", {}).get("message", "")[:300],
            "confidence": meta.get("confidence", ""),
            "subcategory": meta.get("subcategory", []),
        })

    out_file = RESULTS_DIR / f"semgrep_{repo}.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"  {len(output)} findings saved to {out_file.name}")

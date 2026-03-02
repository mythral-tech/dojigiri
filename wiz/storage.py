"""Persistent JSON reports and file hash caching for incremental scans."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import ScanReport, STORAGE_DIR, REPORTS_DIR, CACHE_FILE
from . import __version__


def ensure_dirs():
    """Create storage directories if they don't exist."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def file_hash(filepath: str) -> str:
    """Compute SHA256 hash of file contents."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cache() -> dict:
    """Load file hash cache from disk. Invalidates if version changed."""
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"__version__": __version__}
        # Invalidate cache if version changed
        if data.get("__version__") != __version__:
            return {"__version__": __version__}
        return data
    return {"__version__": __version__}


def save_cache(cache: dict):
    """Save file hash cache to disk."""
    ensure_dirs()
    cache["__version__"] = __version__
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def save_report(report: ScanReport):
    """Save scan report as JSON."""
    ensure_dirs()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report.timestamp = datetime.now().isoformat()
    filename = f"scan_{timestamp}.json"
    filepath = REPORTS_DIR / filename

    data = report.to_dict()
    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Also save as "latest"
    latest = REPORTS_DIR / "latest.json"
    latest.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Auto-prune: keep only last 50 reports
    _prune_reports(max_keep=50)

    return filepath


def _prune_reports(max_keep: int = 50):
    """Remove old reports, keeping only the most recent max_keep."""
    reports = sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True)
    for old in reports[max_keep:]:
        try:
            old.unlink()
        except OSError:
            pass  # Non-critical: file may be in use or already deleted


def load_latest_report() -> Optional[dict]:
    """Load the most recent scan report."""
    latest = REPORTS_DIR / "latest.json"
    if latest.exists():
        try:
            return json.loads(latest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def load_baseline_report(baseline: str) -> Optional[dict]:
    """Load a baseline report for comparison.
    
    Args:
        baseline: Either "latest" or a path to a specific report file
    
    Returns:
        Baseline report dict or None if not found/invalid
    """
    if baseline == "latest":
        return load_latest_report()
    
    # Try to load from specific path
    baseline_path = Path(baseline)
    if not baseline_path.exists():
        return None
    
    try:
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def list_reports() -> list[Path]:
    """List all saved reports, most recent first."""
    ensure_dirs()
    reports = sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True)
    return reports

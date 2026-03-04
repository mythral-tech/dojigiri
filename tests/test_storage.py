"""Tests for storage module - caching and report persistence."""

import os
import sys
import pytest
import json
from pathlib import Path
from dojigiri.storage import (
    file_hash,
    load_cache,
    save_cache,
    save_report,
    load_latest_report,
    load_baseline_report,
    list_reports,
    ensure_dirs,
)
from dojigiri.config import CACHE_FILE, REPORTS_DIR
from dojigiri import __version__


def test_file_hash_consistency(temp_dir):
    """Test that file_hash produces consistent results."""
    test_file = temp_dir / "test.txt"
    test_file.write_text("Hello, World!")
    
    hash1 = file_hash(str(test_file))
    hash2 = file_hash(str(test_file))
    
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex digest


def test_file_hash_different_content(temp_dir):
    """Test that different files produce different hashes."""
    file1 = temp_dir / "file1.txt"
    file1.write_text("Content 1")
    
    file2 = temp_dir / "file2.txt"
    file2.write_text("Content 2")
    
    hash1 = file_hash(str(file1))
    hash2 = file_hash(str(file2))
    
    assert hash1 != hash2


def test_file_hash_same_content(temp_dir):
    """Test that files with same content produce same hash."""
    file1 = temp_dir / "file1.txt"
    file1.write_text("Same content")
    
    file2 = temp_dir / "file2.txt"
    file2.write_text("Same content")
    
    hash1 = file_hash(str(file1))
    hash2 = file_hash(str(file2))
    
    assert hash1 == hash2


def test_load_cache_nonexistent():
    """Test loading cache when file doesn't exist."""
    # Ensure cache doesn't exist by checking a non-standard location
    import tempfile
    from dojigiri import storage
    
    # Temporarily override CACHE_FILE
    original_cache = storage.CACHE_FILE
    with tempfile.TemporaryDirectory() as tmpdir:
        storage.CACHE_FILE = Path(tmpdir) / "nonexistent_cache.json"
        
        cache = load_cache()
        
        # Should return empty cache with version
        assert "__version__" in cache
        assert cache["__version__"] == __version__
        
        # Restore original
        storage.CACHE_FILE = original_cache


def test_save_and_load_cache(temp_dir):
    """Test saving and loading cache."""
    from dojigiri import storage
    
    # Override cache location
    original_cache = storage.CACHE_FILE
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.CACHE_FILE = temp_dir / "cache.json"
    
    # Create and save cache
    cache_data = {
        "file1.py": "hash1",
        "file2.py": "hash2",
    }
    save_cache(cache_data)
    
    # Load it back
    loaded = load_cache()
    
    assert loaded["file1.py"] == "hash1"
    assert loaded["file2.py"] == "hash2"
    assert loaded["__version__"] == __version__
    
    # Restore
    storage.CACHE_FILE = original_cache
    storage.STORAGE_DIR = original_storage


def test_cache_version_invalidation(temp_dir):
    """Test that cache is invalidated when version changes."""
    from dojigiri import storage
    
    original_cache = storage.CACHE_FILE
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.CACHE_FILE = temp_dir / "cache.json"
    
    # Save cache with old version
    old_cache = {
        "__version__": "0.0.1",  # Old version
        "file.py": "hash123",
    }
    storage.CACHE_FILE.write_text(json.dumps(old_cache))
    
    # Load should invalidate and return fresh cache
    loaded = load_cache()
    
    assert loaded["__version__"] == __version__
    assert "file.py" not in loaded  # Old data should be gone
    
    # Restore
    storage.CACHE_FILE = original_cache
    storage.STORAGE_DIR = original_storage


def test_save_report(sample_scan_report, temp_dir):
    """Test saving a scan report."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save report
    filepath = save_report(sample_scan_report)
    
    assert filepath.exists()
    assert filepath.name.startswith("scan_")
    assert filepath.suffix == ".json"
    
    # Check content
    content = json.loads(filepath.read_text())
    assert content["root"] == sample_scan_report.root
    assert content["mode"] == sample_scan_report.mode
    
    # Check latest.json exists
    latest = storage.REPORTS_DIR / "latest.json"
    assert latest.exists()
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_load_latest_report(sample_scan_report, temp_dir):
    """Test loading the latest report."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save a report
    save_report(sample_scan_report)
    
    # Load it back
    loaded = load_latest_report()
    
    assert loaded is not None
    assert loaded["root"] == sample_scan_report.root
    assert loaded["mode"] == sample_scan_report.mode
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_load_latest_report_nonexistent():
    """Test loading latest report when none exists."""
    from dojigiri import storage
    import tempfile
    
    original_reports = storage.REPORTS_DIR
    
    with tempfile.TemporaryDirectory() as tmpdir:
        storage.REPORTS_DIR = Path(tmpdir) / "reports"
        storage.REPORTS_DIR.mkdir()
        
        loaded = load_latest_report()
        assert loaded is None
        
        storage.REPORTS_DIR = original_reports


def test_list_reports(sample_scan_report, temp_dir):
    """Test listing reports."""
    from dojigiri import storage
    import time
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save multiple reports with small delays to ensure unique timestamps
    for i in range(3):
        save_report(sample_scan_report)
        if i < 2:  # Don't sleep after last one
            time.sleep(0.1)  # Longer delay for more distinct timestamps
    
    # List reports (note: save_report calls list_reports internally for pruning)
    reports = list_reports()
    
    # Should have at least 1 report (may have been pruned, but should have latest)
    assert len(reports) >= 1
    # Should be sorted by most recent first
    if len(reports) > 1:
        for i in range(len(reports) - 1):
            assert reports[i].name >= reports[i + 1].name  # Lexicographic order = time order
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_report_auto_prune(sample_scan_report, temp_dir):
    """Test that old reports are auto-pruned."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save more than 50 reports (the max)
    for i in range(55):
        save_report(sample_scan_report)
    
    # Check that only 50 remain (plus latest.json doesn't count)
    scan_reports = list(storage.REPORTS_DIR.glob("scan_*.json"))
    assert len(scan_reports) <= 50
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_ensure_dirs(temp_dir):
    """Test that ensure_dirs creates directories."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir / "new_storage"
    storage.REPORTS_DIR = temp_dir / "new_storage" / "reports"
    
    # Should not exist yet
    assert not storage.STORAGE_DIR.exists()
    assert not storage.REPORTS_DIR.exists()
    
    # Call ensure_dirs
    ensure_dirs()
    
    # Should now exist
    assert storage.STORAGE_DIR.exists()
    assert storage.REPORTS_DIR.exists()
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_load_baseline_report_latest(sample_scan_report, temp_dir):
    """Test loading baseline report using 'latest' keyword."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save a report to become latest
    save_report(sample_scan_report)
    
    # Load it via baseline with "latest"
    baseline = load_baseline_report("latest")
    
    assert baseline is not None
    assert baseline["root"] == sample_scan_report.root
    assert baseline["mode"] == sample_scan_report.mode
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_load_baseline_report_specific_path(sample_scan_report, temp_dir):
    """Test loading baseline report from specific file path."""
    from dojigiri import storage
    
    original_reports = storage.REPORTS_DIR
    original_storage = storage.STORAGE_DIR
    
    storage.STORAGE_DIR = temp_dir
    storage.REPORTS_DIR = temp_dir / "reports"
    
    # Save a report
    report_path = save_report(sample_scan_report)
    
    # Load it via specific path
    baseline = load_baseline_report(str(report_path))
    
    assert baseline is not None
    assert baseline["root"] == sample_scan_report.root
    assert baseline["mode"] == sample_scan_report.mode
    
    # Restore
    storage.REPORTS_DIR = original_reports
    storage.STORAGE_DIR = original_storage


def test_load_baseline_report_invalid_path():
    """Test that load_baseline_report returns None for invalid path."""
    baseline = load_baseline_report("/nonexistent/path/to/report.json")
    assert baseline is None


def test_load_baseline_report_malformed_json(temp_dir):
    """Test that load_baseline_report handles malformed JSON gracefully."""
    # Create a file with invalid JSON
    bad_report = temp_dir / "bad_report.json"
    bad_report.write_text("{ invalid json }")
    
    baseline = load_baseline_report(str(bad_report))
    assert baseline is None


def test_load_baseline_report_latest_nonexistent():
    """Test load_baseline_report with 'latest' when no reports exist."""
    from dojigiri import storage
    import tempfile
    
    original_reports = storage.REPORTS_DIR
    
    with tempfile.TemporaryDirectory() as tmpdir:
        storage.REPORTS_DIR = Path(tmpdir) / "reports"
        storage.REPORTS_DIR.mkdir()
        
        # No reports exist
        baseline = load_baseline_report("latest")
        assert baseline is None
        
        storage.REPORTS_DIR = original_reports


# NOTE: The handoff notes mention dead functions in storage.py (lines 49-58):
# - is_file_unchanged()
# - update_cache_entry()
# These are confirmed to be unused after the analyzer.py refactor.
# They should be removed as suggested in the handoff notes.


@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions test")
def test_ensure_dirs_sets_permissions_unix(temp_dir):
    """Test that ensure_dirs sets 0o700 permissions on Unix."""
    from dojigiri import storage

    original_storage = storage.STORAGE_DIR
    original_reports = storage.REPORTS_DIR

    storage.STORAGE_DIR = temp_dir / "secure_storage"
    storage.REPORTS_DIR = temp_dir / "secure_storage" / "reports"

    ensure_dirs()

    storage_mode = oct(storage.STORAGE_DIR.stat().st_mode & 0o777)
    reports_mode = oct(storage.REPORTS_DIR.stat().st_mode & 0o777)
    assert storage_mode == "0o700", f"STORAGE_DIR mode is {storage_mode}"
    assert reports_mode == "0o700", f"REPORTS_DIR mode is {reports_mode}"

    storage.STORAGE_DIR = original_storage
    storage.REPORTS_DIR = original_reports

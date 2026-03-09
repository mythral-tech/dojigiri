# Dojigiri Test Suite

Comprehensive test suite for the Dojigiri static analysis tool.

## Test Coverage

The test suite includes 1426 tests covering:

### Core Modules (High Priority)
- **test_config.py** - Data structures, enums, and utility functions
- **test_chunker.py** - File chunking logic and token estimation
- **test_languages.py** - Regex rule compilation and pattern matching for all language groups
  - Includes test for known bug: yaml-unsafe regex (lines 319-336)
- **test_detector.py** - Static analysis engine with regex and AST checks
  - Most comprehensive test file covering Python AST analysis
  - Tests for unused imports, exception swallowing, shadowed builtins, complexity detection, etc.

### Integration Tests
- **test_analyzer.py** - File collection, language detection, .doji-ignore support
- **test_storage.py** - Caching, report persistence, and auto-pruning
  - Note: Documents dead functions that should be removed (lines 291-295)

## Running Tests

### Install Dependencies
```bash
pip install pytest
```

### Run All Tests
```bash
# From project root
python -m pytest tests -v

# Or using pytest directly
pytest tests -v
```

### Run Specific Test File
```bash
pytest tests/test_detector.py -v
```

### Run Specific Test
```bash
pytest tests/test_detector.py::test_python_ast_unused_import -v
```

### Run with Coverage (optional)
```bash
pip install pytest-cov
pytest tests --cov=dojigiri --cov-report=html
```

## Test Fixtures

Shared fixtures are defined in `conftest.py`:
- `temp_dir` - Temporary directory for file operations
- `sample_python_code` - Python code with various issues
- `sample_javascript_code` - JavaScript code with issues
- `sample_go_code` - Go code with issues
- `sample_rust_code` - Rust code with issues
- `sample_finding`, `sample_file_analysis`, `sample_scan_report` - Data structure instances

## Known Issues

### Documented Bugs
The test suite includes tests that document known bugs:

1. **yaml-unsafe regex** (test_languages.py:319-336)
   - Pattern incorrectly matches even when SafeLoader is present
   - Commented assertions show expected behavior after fix

### Dead Code
The storage.py module contains unused functions (lines 49-58):
- `is_file_unchanged()`
- `update_cache_entry()`

These should be removed as they are no longer called after the analyzer.py refactor.

## Test Statistics

- **Total Tests**: 1426
- **Pass Rate**: 100% (2 skipped on Windows due to Unix-specific permission checks)
- **Execution Time**: ~55s

## Completed Improvements

All originally planned improvements have been implemented:
- ✅ Baseline/diff mode (`--diff`, `--baseline`)
- ✅ Config file (`.doji.toml`)
- ✅ SARIF output (`--output sarif`)
- ✅ Parallel scanning (worker pool)
- ✅ Block comment support
- ✅ Deep scan cache

# Contributing to Dojigiri

Thanks for your interest in contributing. This guide covers the basics.

## Setup

```bash
git clone https://github.com/mythral-tech/dojigiri
cd dojigiri
pip install -e ".[dev]"
```

This installs the package in editable mode with test dependencies (pytest, etc.).

Tree-sitter grammars are included via `tree-sitter-language-pack`. For LLM features during development, also install `pip install -e ".[llm]"` or `pip install -e ".[all]"`.

## Running Tests

```bash
pytest tests/ -q
```

The full suite (1426 tests) should pass. Two tests may be skipped on Windows due to Unix-specific permission checks. There are no external service dependencies for the test suite -- all LLM calls are mocked.

## Code Style

- Python 3.10+ (match statements, union types with `|`, etc.)
- Type hints encouraged on all public functions. Run `mypy` to check: config is in `pyproject.toml`
- No strict formatter enforced. Keep code consistent with surrounding style
- Imports: standard library first, then third-party, then local. No star imports
- Use `__all__` in package `__init__.py` files

## Project Structure

```
dojigiri/
  __main__.py          CLI entry point
  analyzer.py          Scan orchestration
  detector.py          Static analysis engine
  languages.py         Regex pattern rules
  config.py            Data structures, enums, constants
  semantic/            Tree-sitter analysis (12 modules)
  graph/               Cross-file analysis (3 modules)
  fixer/               Auto-fix engine
```

See ARCHITECTURE.md for the full module map and data flow.

## Adding a New Rule

1. **Pattern rule** (regex): Add a tuple to the appropriate language list in `languages.py`. Each rule needs `(name, severity, category, pattern, message)`. Include CWE/NIST mappings in `compliance.py`.

2. **Semantic rule** (tree-sitter): Add detection logic in the relevant `semantic/` module. If the rule needs a new analysis pass, add it to `detector.py`'s `analyze_file_static()` pipeline.

3. **Tests**: Add test cases in `tests/`. Pattern rules go in `test_languages.py` or `test_detector.py`. Semantic rules get their own test file under the `test_semantic_*` convention.

4. **Documentation**: Add the rule to `doji rules` output by updating `list_all_rules()` in `languages.py`.

## Adding Language Support

Pattern rules (regex) work for any language -- just add a new language group in `languages.py` and register it in `LANGUAGE_EXTENSIONS` in `config.py`.

For semantic analysis (tree-sitter), add a `LanguageConfig` entry in `semantic/lang_config.py` mapping the language's AST node types. Currently supported: Python, JavaScript, TypeScript, Go, Rust, Java, C#.

## Pull Requests

1. Create a branch from `main`
2. Make focused commits (one logical change per commit)
3. Describe what changed and why in the PR description
4. Add or update tests for any new behavior
5. Run the full test suite: `pytest tests/ -q`
6. Run mypy: `mypy dojigiri/`
7. Self-scan: `doji scan dojigiri/` should produce no critical findings

## Reporting Issues

When filing an issue, include:

- Dojigiri version (`doji --version`)
- Python version
- Operating system
- The command you ran
- What you expected vs what happened
- A minimal code sample that reproduces the issue, if applicable
- For false positives: the code being flagged and why it should not be

## License

By contributing, you agree that your contributions will be licensed under the AGPL v3.

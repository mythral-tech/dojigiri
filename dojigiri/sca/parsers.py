"""Lockfile parsers for all supported ecosystems.

Each parser extracts (package_name, version, ecosystem) tuples from lockfiles.
Parsers are intentionally lenient — malformed lines are skipped, not crashed on.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# (package, version, ecosystem)
Dependency = tuple[str, str, str]

# Lockfile name -> parser function mapping
LOCKFILE_PARSERS: dict[str, str] = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements_dev.txt": "pypi",
    "requirements-prod.txt": "pypi",
    "poetry.lock": "pypi",
    "Pipfile.lock": "pypi",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.lock": "crates.io",
    "go.sum": "Go",
    "Gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
}

# Ecosystem display names for OSV API
ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "crates.io": "crates.io",
    "Go": "Go",
    "RubyGems": "RubyGems",
    "Packagist": "Packagist",
}


def parse_lockfile(path: Path) -> list[Dependency]:
    """Parse a lockfile and return dependencies. Dispatches by filename."""
    name = path.name
    if name not in LOCKFILE_PARSERS:
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Failed to read %s: %s", path, e)
        return []

    ecosystem = LOCKFILE_PARSERS[name]
    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem, ecosystem)

    if name == "requirements.txt" or name.startswith("requirements"):
        return _parse_requirements_txt(content, osv_ecosystem)
    elif name == "poetry.lock":
        return _parse_poetry_lock(content, osv_ecosystem)
    elif name == "Pipfile.lock":
        return _parse_pipfile_lock(content, osv_ecosystem)
    elif name == "package-lock.json":
        return _parse_package_lock_json(content, osv_ecosystem)
    elif name == "yarn.lock":
        return _parse_yarn_lock(content, osv_ecosystem)
    elif name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(content, osv_ecosystem)
    elif name == "Cargo.lock":
        return _parse_cargo_lock(content, osv_ecosystem)
    elif name == "go.sum":
        return _parse_go_sum(content, osv_ecosystem)
    elif name == "Gemfile.lock":
        return _parse_gemfile_lock(content, osv_ecosystem)
    elif name == "composer.lock":
        return _parse_composer_lock(content, osv_ecosystem)
    return []


# ─── Individual Parsers ──────────────────────────────────────────────


def _parse_requirements_txt(content: str, ecosystem: str) -> list[Dependency]:
    """Parse pip requirements.txt: `package==version` lines."""
    deps: list[Dependency] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle inline comments
        line = line.split("#")[0].strip()
        # Match package==version or package===version
        m = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*={2,3}\s*(.+)$", line)
        if m:
            deps.append((m.group(1).lower(), m.group(2).strip(), ecosystem))
    return deps


def _parse_poetry_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse poetry.lock TOML: [[package]] sections with name and version."""
    deps: list[Dependency] = []
    # Simple regex-based parsing to avoid tomllib dependency issues
    current_name = None
    current_version = None
    in_package = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if in_package and current_name and current_version:
                deps.append((current_name.lower(), current_version, ecosystem))  # doji:ignore(null-dereference)
            in_package = True
            current_name = None
            current_version = None
        elif in_package:
            m = re.match(r'^name\s*=\s*"(.+?)"', stripped)
            if m:
                current_name = m.group(1)
            m = re.match(r'^version\s*=\s*"(.+?)"', stripped)
            if m:
                current_version = m.group(1)

    # Last package
    if in_package and current_name and current_version:
        deps.append((current_name.lower(), current_version, ecosystem))
    return deps


def _parse_pipfile_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse Pipfile.lock JSON: default and develop sections."""
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for section in ("default", "develop"):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get("version", "")
            if version.startswith("=="):
                version = version[2:]
            if version:
                deps.append((name.lower(), version, ecosystem))
    return deps


def _parse_package_lock_json(content: str, ecosystem: str) -> list[Dependency]:
    """Parse package-lock.json: v2/v3 packages or v1 dependencies."""
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    # v2/v3 format: "packages" key
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # root package
                continue
            # Extract package name from path like "node_modules/foo"
            name = pkg_path.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                deps.append((name, version, ecosystem))
        return deps

    # v1 format: "dependencies" key
    def _walk_v1(dependencies: dict) -> None:
        for name, info in dependencies.items():
            version = info.get("version", "")
            if version:
                deps.append((name, version, ecosystem))
            # Recurse into nested dependencies
            nested = info.get("dependencies", {})
            if nested:
                _walk_v1(nested)

    _walk_v1(data.get("dependencies", {}))
    return deps


def _parse_yarn_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse yarn.lock: name@version blocks with 'version' field."""
    deps: list[Dependency] = []
    seen: set[str] = set()
    current_name: str | None = None

    for line in content.splitlines():
        stripped = line.strip()
        # Match: "  version "1.2.3""
        if stripped.startswith("version "):
            version = stripped.split('"')[1] if '"' in stripped else ""
            if version and current_name and current_name not in seen:
                deps.append((current_name, version, ecosystem))
                seen.add(current_name)
            continue

        # Match package header: "pkg@^1.0.0:" or "pkg@^1.0.0, pkg@^2.0.0:"
        if stripped and not stripped.startswith("#") and stripped.endswith(":"):
            # Extract first package name
            m = re.match(r'^"?(@?[^@"]+)@', stripped)
            if m:
                current_name = m.group(1)  # noqa: F841
            else:
                current_name = None  # noqa: F841

    return deps


def _parse_pnpm_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse pnpm-lock.yaml: package@version entries."""
    deps: list[Dependency] = []
    seen: set[str] = set()

    for line in content.splitlines():
        # Match lines like "  /package@1.2.3:" or "  package@1.2.3:"
        m = re.match(r"^\s+/?(@?[^@\s]+)@(\d[^:()\s]*)", line)
        if m:
            name, version = m.group(1), m.group(2)
            key = f"{name}@{version}"
            if key not in seen:
                deps.append((name, version, ecosystem))
                seen.add(key)
    return deps


def _parse_cargo_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse Cargo.lock TOML: [[package]] sections."""
    deps: list[Dependency] = []
    current_name = None
    current_version = None
    in_package = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if in_package and current_name and current_version:
                deps.append((current_name, current_version, ecosystem))
            in_package = True
            current_name = None
            current_version = None
        elif in_package:
            m = re.match(r'^name\s*=\s*"(.+?)"', stripped)
            if m:
                current_name = m.group(1)
            m = re.match(r'^version\s*=\s*"(.+?)"', stripped)
            if m:
                current_version = m.group(1)

    if in_package and current_name and current_version:
        deps.append((current_name, current_version, ecosystem))
    return deps


def _parse_go_sum(content: str, ecosystem: str) -> list[Dependency]:
    """Parse go.sum: module version hash lines."""
    deps: list[Dependency] = []
    seen: set[str] = set()

    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        module = parts[0]
        version = parts[1]
        # Strip /go.mod suffix and v prefix
        version = version.replace("/go.mod", "")
        if version.startswith("v"):
            version = version[1:]
        key = f"{module}@{version}"
        if key not in seen:
            deps.append((module, version, ecosystem))
            seen.add(key)
    return deps


def _parse_gemfile_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse Gemfile.lock: specs section with indented gem (version) lines."""
    deps: list[Dependency] = []
    in_specs = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not line.startswith(" ") and not line.startswith("\t"):
                in_specs = False
                continue
            # Match "    gem_name (1.2.3)"
            m = re.match(r"^\s{4}(\S+)\s+\((\S+)\)$", line)
            if m:
                deps.append((m.group(1), m.group(2), ecosystem))
    return deps


def _parse_composer_lock(content: str, ecosystem: str) -> list[Dependency]:
    """Parse composer.lock JSON: packages and packages-dev arrays."""
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if version.startswith("v"):
                version = version[1:]
            if name and version:
                deps.append((name, version, ecosystem))
    return deps


def discover_lockfiles(root: Path) -> list[Path]:
    """Walk root directory and find all recognized lockfiles."""
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "vendor", "target"}
    lockfiles: list[Path] = []

    for item in root.rglob("*"):
        if any(part in skip_dirs for part in item.parts):
            continue
        if item.is_file() and item.name in LOCKFILE_PARSERS:
            lockfiles.append(item)

    return sorted(lockfiles)

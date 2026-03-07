"""Build Dojigiri as a standalone .exe using Nuitka.

Prerequisites:
    pip install nuitka zstandard
    # Nuitka auto-downloads MinGW64 C compiler on Windows if needed

Usage:
    python build_exe.py

Output:
    dist/doji.exe
"""

import subprocess
import sys
from pathlib import Path

# The 6 language bindings Dojigiri uses from tree_sitter_language_pack/bindings/
# (csharp comes from the separate tree_sitter_c_sharp package)
NEEDED_BINDINGS = ["python", "javascript", "typescript", "go", "rust", "java"]


def _find_package_dir(package_name: str) -> Path:
    """Find the installed location of a package."""
    mod = __import__(package_name)
    return Path(mod.__file__).parent


def _build_data_file_args() -> list[str]:
    """Build --include-data-files args for selective .pyd inclusion."""
    args = []
    tslp_dir = _find_package_dir("tree_sitter_language_pack")
    bindings_dir = tslp_dir / "bindings"

    for name in NEEDED_BINDINGS:
        pyd = bindings_dir / f"{name}.pyd"
        if pyd.exists():
            args.append(
                f"--include-data-files={pyd}=tree_sitter_language_pack/bindings/{name}.pyd"
            )
        else:
            print(f"WARNING: {pyd} not found, skipping", file=sys.stderr)

    return args


cmd = [
    sys.executable, "-m", "nuitka",
    "--mode=onefile",
    "--output-dir=dist",
    "--output-filename=doji.exe",
    "--python-flag=-m",
    "--assume-yes-for-downloads",
    "--onefile-no-compression",

    # Bundle all dojigiri code (compiled to C)
    "--include-package=dojigiri",

    # Bundle tree-sitter core
    "--include-package=tree_sitter",

    # Bundle tree_sitter_language_pack loader (compiled to C)
    "--include-module=tree_sitter_language_pack",
    "--include-module=tree_sitter_language_pack.bindings",

    # Bundle tree_sitter_c_sharp (separate package, used for csharp)
    "--include-package=tree_sitter_c_sharp",

    # Note: we do NOT use --nofollow-import-to for tree_sitter_language_pack.bindings
    # because that would block runtime imports. The .pyd data files are included
    # selectively below and will be found via import_module at runtime.

    # tree_sitter_yaml and tree_sitter_embedded_template are small (~200KB)
    # and imported at top level by tree_sitter_language_pack — must be included
    "--include-package=tree_sitter_yaml",
    "--include-package=tree_sitter_embedded_template",

    # Don't bundle LLM dependencies (optional, not needed for .exe)
    "--nofollow-import-to=anthropic",
    "--nofollow-import-to=httpx",
    "--nofollow-import-to=httpcore",
    "--nofollow-import-to=mcp",
]

# Include needed .pyd bindings as data files (~4MB total vs 170MB)
# These are loaded by the ctypes fallback in tree_sitter_language_pack
cmd += _build_data_file_args()

cmd += [
    # Product metadata (Windows)
    "--company-name=Dojigiri",
    "--product-name=Dojigiri Static Analyzer",
    f"--product-version={__import__('dojigiri').__version__}",
    "--file-description=Static analysis and code quality tool",

    # Windows console app
    "--windows-console-mode=force",

    # Entry point
    "dojigiri",
]

print("Building doji.exe with Nuitka...")
print("This takes 5-10 minutes on first build.\n")
print(f"Command: {' '.join(cmd)}\n")

result = subprocess.run(cmd)
if result.returncode == 0:
    print("\nBuild successful! Output: dist/doji.exe")
else:
    print(f"\nBuild failed with exit code {result.returncode}", file=sys.stderr)
    sys.exit(result.returncode)

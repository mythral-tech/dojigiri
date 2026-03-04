"""Fix engine — deterministic fixers, LLM fix orchestration, fix application."""

import ast
import logging
import os
import re
import shutil
import sys
import tempfile
from typing import Optional, Protocol

logger = logging.getLogger(__name__)

from .config import (
    Finding, Fix, FixReport, FixSource, FixStatus, Severity,
)


# ─── String-context helpers ───────────────────────────────────────────


_STRING_LITERAL_RE = re.compile(
    r'""".*?"""|'
    r"'''.*?'''|"
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'"
)


def _in_multiline_string(content: str, line_num: int) -> bool:
    """Check if a 1-indexed line is inside a multiline triple-quoted string."""
    lines = content.splitlines()
    in_triple = False
    for i, cur_line in enumerate(lines):
        if i + 1 == line_num:
            return in_triple
        stripped = cur_line.strip()
        for tq in ('"""', "'''"):
            if stripped.count(tq) % 2 == 1:
                in_triple = not in_triple
    return False


def _pattern_outside_strings(line: str, pattern: re.Pattern) -> bool:
    """Check if pattern matches in code portions of a line (outside string literals)."""
    code_only = _STRING_LITERAL_RE.sub(lambda m: ' ' * len(m.group()), line)
    return bool(pattern.search(code_only))


class FixerFn(Protocol):
    """Deterministic fix generator: receives a single line + context, returns a fix or None."""

    def __call__(self, line: str, finding: Finding, content: str) -> Optional[Fix]: ...


# ─── Deterministic fixers ────────────────────────────────────────────
# Each takes (line, finding, full_content) and returns Fix | None.


def _fix_unused_import(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Remove an unused import line."""
    stripped = line.strip()
    if stripped.startswith("import ") or stripped.startswith("from "):
        # Skip multiline imports — opening paren without closing on same line
        if '(' in stripped and ')' not in stripped:
            return None
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code="",
            explanation=f"Removed unused import: {stripped}",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_bare_except(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace bare `except:` with `except Exception:`."""
    m = re.match(r'^(\s*)except\s*:', line)
    if m:
        indent = m.group(1)
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=f"{indent}except Exception:\n",
            explanation="Replaced bare except with 'except Exception:' to avoid catching SystemExit/KeyboardInterrupt",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_loose_equality(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace == with === and != with !== in JS/TS."""
    # Preserve == null idiom (checks both null and undefined intentionally)
    code_only = _STRING_LITERAL_RE.sub(lambda m: ' ' * len(m.group()), line)
    if re.search(r'(?<!=)==(?!=)\s*null\b', code_only) or re.search(r'(?<!=)!=(?!=)\s*null\b', code_only):
        return None
    new_line = line
    # Replace != before == to avoid double-replacing !== back
    new_line = re.sub(r'(?<!=)!=(?!=)', '!==', new_line)
    new_line = re.sub(r'(?<!=)==(?!=)', '===', new_line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced loose equality with strict equality",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_var_usage(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace `var` with `let`."""
    m = re.match(r'^(\s*)var\s+(\w+)', line)
    if not m:
        return None
    var_name = m.group(2)
    indent = m.group(1)

    # Skip if var is inside a block scope (if/for/while/switch) — let would
    # break references outside the block since let has block scoping.
    lines = content.splitlines()
    line_idx = finding.line - 1
    indent_len = len(indent)
    # Walk backwards to see if we're inside a block
    for i in range(line_idx - 1, -1, -1):
        prev = lines[i]
        stripped = prev.strip()
        if not stripped:
            continue
        prev_indent = len(prev) - len(prev.lstrip())
        if prev_indent < indent_len:
            # We found a line at a shallower indent — check if it's a block opener
            if re.match(r'\s*(?:if|else|for|while|switch|try|catch|finally|do)\b', prev):
                return None  # var is inside a block scope, skip
            if stripped == '{':
                return None  # bare block scope
            break

    new_line = re.sub(r'^(\s*)var\b', r'\1let', line)
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_line,
        explanation="Replaced 'var' with 'let' for block scoping",
        source=FixSource.DETERMINISTIC,
    )


def _fix_none_comparison(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace `== None` with `is None`, `!= None` with `is not None`."""
    # Skip if match is inside a string literal or multiline string
    if not _pattern_outside_strings(line, re.compile(r'(?:==|!=)\s*None\b')):
        return None
    if _in_multiline_string(content, finding.line):
        return None
    new_line = line
    new_line = re.sub(r'!=\s*None\b', 'is not None', new_line)
    new_line = re.sub(r'==\s*None\b', 'is None', new_line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Use identity comparison for None (PEP 8)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_type_comparison(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace `type(x) == Y` with `isinstance(x, Y)`."""
    m = re.search(r'type\(([^)]+)\)\s*==\s*(\w+)', line)
    if m:
        var = m.group(1).strip()
        typ = m.group(2).strip()
        new_line = line[:m.start()] + f"isinstance({var}, {typ})" + line[m.end():]
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation=f"Use isinstance() instead of type() comparison for proper subclass support",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_console_log(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Remove console.log() line — only if it's the sole statement."""
    if "console.log" not in line:
        return None
    stripped = line.strip().rstrip(';').strip()
    # If the line has other statements (semicolons outside the console.log call),
    # or is chained, skip instead of deleting the whole line.
    # Match a standalone console.log(...) call
    if not re.match(r'^console\.log\s*\(.*\)\s*;?\s*$', stripped):
        return None
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation="Removed console.log() debug statement",
        source=FixSource.DETERMINISTIC,
    )


def _fix_insecure_http(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace http:// with https:// in URLs."""
    # Skip if line is inside a multiline string (docstring)
    if _in_multiline_string(content, finding.line):
        return None
    # Skip single-line docstrings
    stripped = line.strip()
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return None
    # Skip localhost and internal URLs — these legitimately use HTTP
    new_line = re.sub(
        r'http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])',
        'https://', line,
    )
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Upgraded insecure HTTP URL to HTTPS",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_fstring_no_expr(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Remove f-prefix from f-strings with no expressions."""
    # Match f"..." or f'...' where content has no { }
    new_line = re.sub(r"""\bf(["'])([^{}]*?)\1""", r'\1\2\1', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Removed unnecessary f-string prefix (no expressions)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_hardcoded_secret(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace hardcoded secret with os.environ lookup."""
    # Skip test files — secrets there are usually fixtures, not real
    basename = os.path.basename(finding.file)
    dirparts = finding.file.replace('\\', '/').split('/')
    if (basename.startswith('test_') or basename.endswith(('_test.py', '.test.js', '.test.ts',
            '.spec.js', '.spec.ts')) or '__tests__' in dirparts):
        return None
    # Match: VAR_NAME = "secret_value" or VAR_NAME = 'secret_value'
    m = re.match(r'^(\s*)(\w+)\s*=\s*["\'].*?["\']', line)
    if not m:
        return None
    indent = m.group(1)
    var_name = m.group(2)
    new_line = f'{indent}{var_name} = os.environ["{var_name}"]\n'
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_line,
        explanation=f"Replaced hardcoded secret with os.environ[\"{var_name}\"]",
        source=FixSource.DETERMINISTIC,
    )


def _fix_open_without_with(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Wrap `x = open(...)` in a `with` statement."""
    m = re.match(r'^(\s*)(\w+)\s*=\s*open\((.+)\)\s*$', line.rstrip("\n"))
    if not m:
        return None
    indent = m.group(1)
    var_name = m.group(2)
    open_args = m.group(3)

    # Find subsequent lines that use this variable, up to the next blank/return/def
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    body_lines = []
    for i in range(line_idx + 1, len(lines)):
        subsequent = lines[i]
        stripped = subsequent.strip()
        if not stripped or stripped.startswith("def ") or stripped.startswith("class "):
            break
        # Check if this line is at the same or deeper indentation
        if subsequent.rstrip() and not subsequent.startswith(indent + " ") and not subsequent.startswith(indent + "\t"):
            if not subsequent.startswith(indent):
                break
            # Same indent level — include if it uses the variable, else stop
            if var_name not in subsequent:
                break
        body_lines.append(subsequent)

    if not body_lines:
        # Can't determine the body — just wrap the single line
        new_code = f"{indent}with open({open_args}) as {var_name}:\n"
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_code,
            explanation="Wrapped open() in 'with' statement for automatic cleanup",
            source=FixSource.DETERMINISTIC,
        )

    # Build the with block with re-indented body
    new_code = f"{indent}with open({open_args}) as {var_name}:\n"
    for bl in body_lines:
        # Add one level of indentation
        if bl.strip():
            new_code += indent + "    " + bl.lstrip()
        else:
            new_code += bl

    # Set end_line so apply_fixes blanks out the original body lines
    last_body_line = finding.line + len(body_lines)
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_code,
        explanation="Wrapped open() in 'with' statement for automatic cleanup",
        source=FixSource.DETERMINISTIC,
        end_line=last_body_line,
    )


def _fix_yaml_unsafe(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace yaml.load() with yaml.safe_load()."""
    # Skip if SafeLoader or Loader= already present on this line
    if "SafeLoader" in line or "Loader=" in line:
        return None
    new_line = re.sub(r'\byaml\.load\s*\(', 'yaml.safe_load(', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced yaml.load() with yaml.safe_load() to prevent arbitrary code execution",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_weak_hash(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace hashlib.md5/sha1 with hashlib.sha256."""
    # Skip if usedforsecurity=False is present (legitimate non-crypto use)
    if "usedforsecurity=False" in line or "usedforsecurity = False" in line:
        return None
    new_line = re.sub(r'\bhashlib\.(?:md5|sha1)\s*\(', 'hashlib.sha256(', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced weak hash (MD5/SHA1) with SHA-256",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_unreachable_code(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Delete a single unreachable line after return/raise/break/continue."""
    stripped = line.strip()
    # Only fix simple single-line statements, not block starters
    if stripped.endswith(":") or not stripped:
        return None
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation=f"Removed unreachable code: {stripped}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_mutable_default(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace mutable default argument with None + body guard."""
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Collect the full function def (may span multiple lines with backslash or parens)
    def_line = lines[line_idx]
    m = re.match(r'^(\s*)(async\s+)?def\s+\w+\s*\(', def_line)
    if not m:
        return None
    indent = m.group(1)

    # Find the end of the def signature (line with closing `):`
    sig_end = line_idx
    sig_text = def_line
    if ')' not in def_line or ':' not in def_line.split(')')[-1]:
        for i in range(line_idx + 1, min(line_idx + 20, len(lines))):
            sig_text += lines[i]
            sig_end = i
            if ')' in lines[i]:
                break

    # Find mutable defaults and replace them
    # Match param=[] or param={} or param=set()
    new_sig = sig_text
    guards = []
    for match in re.finditer(r'(\w+)\s*=\s*(\[\]|\{\}|set\(\))', sig_text):
        param = match.group(1)
        mutable = match.group(2)
        new_sig = new_sig.replace(f"{param}={mutable}", f"{param}=None", 1)
        new_sig = new_sig.replace(f"{param} = {mutable}", f"{param}=None", 1)
        guards.append((param, mutable))

    if not guards:
        return None

    # Build guard lines
    body_indent = indent + "    "
    guard_lines = ""
    for param, mutable in guards:
        guard_lines += f"{body_indent}if {param} is None:\n"
        guard_lines += f"{body_indent}    {param} = {mutable}\n"

    # If next line after signature is a docstring, place guard after docstring
    next_idx = sig_end + 1
    if next_idx < len(lines):
        next_stripped = lines[next_idx].strip()
        ds_match = re.match(r'^[brufBRUF]{0,2}("""|\'\'\')', next_stripped)
        if ds_match:
            quote = ds_match.group(1)
            # Check if docstring closes on same line (after the opening)
            rest = next_stripped[ds_match.end():]
            if quote in rest:
                # Single-line docstring — include it in new_sig, guards go after
                new_sig += lines[next_idx]
                sig_end = next_idx
            else:
                # Multi-line docstring — find the closing triple-quote
                new_sig += lines[next_idx]
                for di in range(next_idx + 1, len(lines)):
                    new_sig += lines[di]
                    sig_end = di
                    if quote in lines[di]:
                        break

    fixed_code = new_sig + guard_lines
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=def_line, fixed_code=fixed_code,
        explanation="Replaced mutable default argument with None + guard clause",
        source=FixSource.DETERMINISTIC,
        end_line=sig_end + 1 if sig_end > line_idx else None,
    )


def _fix_unused_variable(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Remove an unused variable assignment."""
    stripped = line.strip()

    # JS/TS: const x = ...; / let x = ...; / var x = ...;
    js_m = re.match(r'^(const|let|var)\s+(\w+)\s*=\s*(.+?);?\s*$', stripped)
    if js_m:
        var_name = js_m.group(2)
        rhs = js_m.group(3).strip()
        # Skip if RHS has side effects (function calls other than safe constructors)
        if re.search(r'\w+\s*\(', rhs) and not re.match(r'^["\'\d\[\{(]', rhs):
            if 'require(' not in rhs:  # require() is an import, safe to remove
                return None
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code="",
            explanation=f"Removed unused variable: {var_name}",
            source=FixSource.DETERMINISTIC,
        )

    # Python: x = <value>
    if not re.match(r'^\w+\s*=\s*', stripped):
        return None
    # Don't remove if it's a type annotation (x: int = 5)
    if re.match(r'^\w+\s*:', stripped):
        return None
    # Don't remove if it looks like a destructuring or multi-assignment
    if ',' in stripped.split('=')[0]:
        return None
    # Don't remove if the RHS has side effects (function calls, method calls, chained calls)
    rhs = stripped.split('=', 1)[1].strip()
    if re.search(r'\w+\s*\(', rhs) or re.search(r'\.\w+\s*\(', rhs):
        safe_calls = ('True', 'False', 'None', '[]', '{}', '""', "''", '0', 'set()', 'dict()', 'list()', 'tuple()')
        if rhs not in safe_calls and not re.match(r'^["\'\d\[\{(]', rhs):
            return None
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation=f"Removed unused variable: {stripped.split('=')[0].strip()}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_os_system(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace os.system() with subprocess.run()."""
    m = re.search(r'os\.system\((.+)\)', line)
    if not m:
        return None
    cmd_arg = m.group(1).strip()
    indent = re.match(r'^(\s*)', line).group(1)
    new_line = f"{indent}subprocess.run({cmd_arg}, shell=True)\n"
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_line,
        explanation="Replaced os.system() with subprocess.run() (safer, returns exit info)",
        source=FixSource.DETERMINISTIC,
    )


def _fix_eval_usage(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace eval() with safe alternative: ast.literal_eval (Python), JSON.parse (JS/TS)."""
    m = re.search(r'\beval\s*\((.+)\)', line)
    if not m:
        return None
    eval_arg = m.group(1).strip()

    if finding.file.endswith('.py'):
        replacement = f"ast.literal_eval({eval_arg})"
        new_line = line[:m.start()] + replacement + line[m.end():]
        # Add inline warning if not already commented
        if '#' not in new_line:
            new_line = new_line.rstrip('\n') + "  # NOTE: only works for literal expressions\n"
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced eval() with ast.literal_eval() (safe for literals, rejects arbitrary code)",
            source=FixSource.DETERMINISTIC,
        )

    if finding.file.endswith(('.js', '.ts', '.jsx', '.tsx')):
        new_line = line[:m.start()] + f"JSON.parse({eval_arg})" + line[m.end():]
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced eval() with JSON.parse() (safe — rejects arbitrary code execution)",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_sql_injection(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Replace string-concatenated SQL with parameterized query."""
    # Only fix Python files
    if not finding.file.endswith('.py'):
        return None
    indent = re.match(r'^(\s*)', line).group(1)

    # Pattern 1: cursor.execute(f"...{var}...")
    m = re.match(r'^(\s*)(\w+)\.execute\(f(["\'])(.+)\3\)', line.rstrip())
    if m:
        call_obj = m.group(2)
        sql_body = m.group(4)
        # Extract interpolated variables
        params = re.findall(r'\{(\w+)\}', sql_body)
        if not params:
            return None
        # Replace {var} with ? placeholders
        clean_sql = re.sub(r"'\{(\w+)\}'", "?", sql_body)
        clean_sql = re.sub(r"\{(\w+)\}", "?", clean_sql)
        param_tuple = ", ".join(params)
        new_line = f"{indent}{call_obj}.execute(\"{clean_sql}\", ({param_tuple},))\n"
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced string interpolation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    # Pattern 2: "SELECT ... WHERE x = " + var
    m = re.match(r'^(\s*)(\w+)\s*=\s*(["\'])(.+?)\3\s*\+\s*(\w+)', line.rstrip())
    if m:
        var_name = m.group(2)
        sql_body = m.group(4)
        param_var = m.group(5)
        new_line = f'{indent}{var_name} = "{sql_body} ?"\n'
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation=f"Replaced string concatenation with ? placeholder (pass ({param_var},) as second arg to execute())",
            source=FixSource.DETERMINISTIC,
        )

    # Pattern 3: conn.execute("..." + var)
    m = re.match(r'^(\s*)(\w+)\.execute\((["\'])(.+?)\3\s*\+\s*(\w+)\)', line.rstrip())
    if m:
        call_obj = m.group(2)
        sql_body = m.group(4)
        param_var = m.group(5)
        new_line = f'{indent}{call_obj}.execute("{sql_body} ?", ({param_var},))\n'
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced string concatenation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_resource_leak(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Add .close() for unclosed resources (connections, cursors, file handles)."""
    if not finding.file.endswith('.py'):
        return None

    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Extract the variable name from the source line: var = something(...)
    src = lines[line_idx]
    m = re.match(r'^(\s*)(\w+)\s*=\s*', src)
    if not m:
        return None
    var_name = m.group(2)

    # Find the containing function
    func_indent = None
    for i in range(line_idx - 1, -1, -1):
        fm = re.match(r'^(\s*)(async\s+)?def\s+', lines[i])
        if fm:
            func_indent = fm.group(1)
            break
    if func_indent is None:
        return None

    body_indent = func_indent + "    "

    # Scan forward to find the function body lines and the last return
    body_lines = []  # (index, stripped) for lines in this function body
    for i in range(line_idx + 1, len(lines)):
        stripped = lines[i].strip()
        if not stripped:
            continue
        cur_indent = len(lines[i]) - len(lines[i].lstrip())
        # Stop at anything at function-level indent or less: decorators, defs, classes, module code
        if cur_indent <= len(func_indent) and stripped:
            break
        body_lines.append((i, stripped))

    if not body_lines:
        return None

    # Check if the variable is returned — if so, can't close it
    for idx, stripped in body_lines:
        if stripped.startswith('return') and var_name in stripped:
            return None

    # Skip functions with multiple returns or try/except (too complex for safe fix)
    return_count = sum(1 for _, s in body_lines if s.startswith('return') or s == 'return')
    has_try = any(s.startswith('try:') for _, s in body_lines)
    if return_count > 1 or has_try:
        return None

    # Find the last return in the function body
    last_return_idx = None
    for idx, stripped in body_lines:
        if stripped.startswith('return') or stripped == 'return':
            last_return_idx = idx

    if last_return_idx is not None:
        # Insert .close() BEFORE the return
        return_line = lines[last_return_idx]
        close_line = f"{body_indent}{var_name}.close()\n"
        new_code = close_line + return_line
        return Fix(
            file=finding.file, line=last_return_idx + 1, rule=finding.rule,
            original_code=return_line, fixed_code=new_code,
            explanation=f"Added {var_name}.close() before return to prevent resource leak",
            source=FixSource.DETERMINISTIC,
        )

    # No return — add .close() after the last body line
    last_idx = body_lines[-1][0]
    last_line = lines[last_idx]
    close_line = f"{body_indent}{var_name}.close()\n"
    new_code = last_line.rstrip('\n') + '\n' + close_line
    return Fix(
        file=finding.file, line=last_idx + 1, rule=finding.rule,
        original_code=last_line, fixed_code=new_code,
        explanation=f"Added {var_name}.close() to prevent resource leak",
        source=FixSource.DETERMINISTIC,
    )


def _fix_exception_swallowed(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Add TODO comment to bare except: pass blocks."""
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1  # finding.line points to the except handler
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Find the `pass` line in the except body (should be next non-empty line)
    pass_idx = None
    for i in range(line_idx + 1, min(line_idx + 5, len(lines))):
        stripped = lines[i].strip()
        if stripped == "pass":
            pass_idx = i
            break
        if stripped and stripped != "pass":
            break  # Body isn't just `pass`, skip

    if pass_idx is None:
        return None

    # Replace pass with pass + TODO
    pass_line = lines[pass_idx]
    m = re.match(r'^(\s*)', pass_line)
    pass_indent = m.group(1) if m else ""
    new_pass = f"{pass_indent}pass  # TODO: handle this exception\n"
    return Fix(
        file=finding.file, line=pass_idx + 1, rule=finding.rule,
        original_code=pass_line, fixed_code=new_pass,
        explanation="Added TODO comment to silently swallowed exception",
        source=FixSource.DETERMINISTIC,
    )


DETERMINISTIC_FIXERS: dict[str, FixerFn] = {
    "unused-import": _fix_unused_import,
    "unused-variable": _fix_unused_variable,
    "bare-except": _fix_bare_except,
    "loose-equality": _fix_loose_equality,
    "var-usage": _fix_var_usage,
    "none-comparison": _fix_none_comparison,
    "type-comparison": _fix_type_comparison,
    "console-log": _fix_console_log,
    "insecure-http": _fix_insecure_http,
    "fstring-no-expr": _fix_fstring_no_expr,
    "hardcoded-secret": _fix_hardcoded_secret,
    "open-without-with": _fix_open_without_with,
    "yaml-unsafe": _fix_yaml_unsafe,
    "weak-hash": _fix_weak_hash,
    "unreachable-code": _fix_unreachable_code,
    "mutable-default": _fix_mutable_default,
    "exception-swallowed": _fix_exception_swallowed,
    "resource-leak": _fix_resource_leak,
    "os-system": _fix_os_system,
    "eval-usage": _fix_eval_usage,
    "sql-injection": _fix_sql_injection,
}


# ─── LLM fix integration ─────────────────────────────────────────────


def generate_llm_fixes(
    filepath: str, content: str, language: str,
    findings: list[Finding], cost_tracker=None,
) -> list[Fix]:
    """Send findings to LLM, get back structured fixes.

    Falls back gracefully if LLM is unavailable.
    """
    if not findings:
        return []

    try:
        from .llm import fix_file as llm_fix_file, CostTracker, LLMError
        if cost_tracker is None:
            cost_tracker = CostTracker()

        findings_dicts = []
        for f in findings:
            findings_dicts.append({
                "line": f.line,
                "rule": f.rule,
                "message": f.message,
                "suggestion": f.suggestion or "",
            })

        raw_fixes, cost_tracker = llm_fix_file(
            content, filepath, language, findings_dicts, cost_tracker,
        )

        fixes = []
        for rf in raw_fixes:
            try:
                fixes.append(Fix(
                    file=filepath,
                    line=rf.get("line", 0),
                    rule=rf.get("rule", "llm-fix"),
                    original_code=rf.get("original_code", ""),
                    fixed_code=rf.get("fixed_code", ""),
                    explanation=rf.get("explanation", "LLM-generated fix"),
                    source=FixSource.LLM,
                ))
            except (KeyError, TypeError):
                continue

        return fixes

    except (LLMError, OSError, ValueError) as e:
        logger.warning("LLM fix generation failed: %s", e)
        return []


# ─── Fix application engine ──────────────────────────────────────────


def apply_fixes(
    filepath: str, fixes: list[Fix],
    dry_run: bool = True, create_backup: bool = True,
) -> list[Fix]:
    """Apply fixes to a file. Bottom-to-top to preserve line numbers.

    Returns the list of fixes with updated statuses.
    """
    if not fixes:
        return fixes

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        for fix in fixes:
            fix.status = FixStatus.FAILED
        logger.warning("Cannot read %s: %s", filepath, e)
        return fixes

    lines = content.splitlines(keepends=True)

    # Sort by line descending so we apply from bottom up
    indexed_fixes = sorted(enumerate(fixes), key=lambda x: x[1].line, reverse=True)

    occupied_lines: set[int] = set()
    deleted_indices: set[int] = set()  # Track lines blanked by fixes (not original blank lines)

    for idx, fix in indexed_fixes:
        # Determine the full line range this fix covers
        start_line = fix.line
        end_line = fix.end_line if fix.end_line is not None else fix.line
        fix_range = set(range(start_line, end_line + 1))

        if fix_range & occupied_lines:
            fix.status = FixStatus.SKIPPED
            continue

        # Validate: check that original_code matches the actual file content
        line_idx = fix.line - 1  # 0-based
        if line_idx < 0 or line_idx >= len(lines):
            fix.status = FixStatus.FAILED
            continue

        # For deletion fixes (empty fixed_code), remove the line(s)
        if fix.original_code and not fix.fixed_code:
            # Verify original matches
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() not in actual:
                fix.status = FixStatus.FAILED
                continue
            if not dry_run:
                # Blank out all lines in the range
                for li in range(line_idx, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        elif fix.original_code and fix.fixed_code:
            # Replacement fix — verify original is present
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() not in actual:
                fix.status = FixStatus.FAILED
                continue
            if not dry_run:
                # Replace the first line with fixed_code
                new_code = fix.fixed_code
                if not new_code.endswith("\n") and actual.endswith("\n"):
                    new_code += "\n"
                lines[line_idx] = new_code
                # Blank out remaining lines in range (line+1..end_line)
                for li in range(line_idx + 1, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        else:
            fix.status = FixStatus.FAILED

    if not dry_run:
        # Remove only lines that were blanked by fixes, not original blank lines
        new_content = "".join(line for i, line in enumerate(lines) if i not in deleted_indices)

        # Backup
        if create_backup:
            backup_path = filepath + ".wiz.bak"
            try:
                shutil.copy2(filepath, backup_path)
            except OSError as e:
                logger.warning("Could not create backup: %s", e)

        # Atomic write: write to temp file, then rename
        try:
            dir_name = os.path.dirname(filepath) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".wiz.tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(new_content)
                # On Windows, we need to remove the target first
                if sys.platform == "win32" and os.path.exists(filepath):
                    os.replace(tmp_path, filepath)
                else:
                    os.rename(tmp_path, filepath)
            except (OSError, ValueError):  # cleanup-and-reraise for temp file
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.warning("Error writing %s: %s", filepath, e)
            for fix in fixes:
                if fix.status == FixStatus.APPLIED:
                    fix.status = FixStatus.FAILED

    return fixes


# ─── Fix verification ─────────────────────────────────────────────────


def verify_fixes(filepath: str, language: str,
                 pre_findings: list[Finding],
                 custom_rules=None) -> dict:
    """Re-scan a file after fixes and compare before/after.

    Uses 5-line bucket matching to determine which issues were resolved
    and whether any new issues were introduced.

    Returns dict with:
      - resolved: int (issues that were fixed)
      - remaining: int (issues still present)
      - new_issues: int (issues introduced by fixes)
      - new_findings: list of new Finding dicts
    """
    from .detector import analyze_file_static

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            new_content = f.read()
    except OSError:
        return {"resolved": 0, "remaining": 0, "new_issues": 0, "new_findings": [],
                "error": f"Could not re-read {filepath}"}

    post_findings = analyze_file_static(filepath, new_content, language,
                                        custom_rules=custom_rules)

    # Compare by rule counts: for each rule, how many before vs after.
    # Increase in count for a rule = new issues. Decrease = resolved.
    from collections import Counter
    pre_counts = Counter(f.rule for f in pre_findings)
    post_counts = Counter(f.rule for f in post_findings)

    all_rules = set(pre_counts) | set(post_counts)
    resolved = 0
    remaining = 0
    new_issues = 0
    for rule in all_rules:
        before = pre_counts.get(rule, 0)
        after = post_counts.get(rule, 0)
        if after <= before:
            resolved += before - after
            remaining += after
        else:
            remaining += before
            new_issues += after - before

    new_findings = []
    # Only report findings with rules not present at all before
    pre_rules = set(pre_counts)
    for finding in post_findings:
        if finding.rule not in pre_rules:
            new_findings.append(finding.to_dict())

    return {
        "resolved": resolved,
        "remaining": remaining,
        "new_issues": new_issues,
        "new_findings": new_findings,
    }


# ─── Post-fix validation & rollback ──────────────────────────────────


def _validate_syntax(filepath: str, content: str, language: str) -> Optional[str]:
    """Validate syntax of fixed file. Returns error message or None if valid."""
    if language == "python":
        try:
            ast.parse(content, filename=filepath)
        except SyntaxError as e:
            return f"Python syntax error: {e.msg} (line {e.lineno})"
    elif language in ("javascript", "typescript"):
        # Lightweight check: balanced braces, parens, brackets
        # Strip string literals, template literals, and comments first
        # to avoid counting delimiters inside non-code regions.
        stripped = re.sub(r'`(?:[^`\\]|\\.)*`', '', content)        # template literals
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '', stripped)        # double-quoted strings
        stripped = re.sub(r"'(?:[^'\\]|\\.)*'", '', stripped)        # single-quoted strings
        stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)  # block comments
        stripped = re.sub(r'//[^\n]*', '', stripped)                  # line comments
        counts = {'(': 0, '[': 0, '{': 0}
        closers = {')': '(', ']': '[', '}': '{'}
        for ch in stripped:
            if ch in counts:
                counts[ch] += 1
            elif ch in closers:
                counts[closers[ch]] -= 1
        for opener, count in counts.items():
            if count != 0:
                closer = {'(': ')', '[': ']', '{': '}'}[opener]
                return f"Unbalanced '{opener}'/'{closer}' (off by {count})"
    return None


def _rollback_from_backup(filepath: str, fixes: list[Fix]) -> None:
    """Restore file from .wiz.bak backup and mark all applied fixes as FAILED."""
    backup_path = filepath + ".wiz.bak"
    if os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, filepath)
            logger.info("Rolled back %s from backup", filepath)
        except OSError as e:
            logger.warning("Rollback failed for %s: %s", filepath, e)
    for fix in fixes:
        if fix.status == FixStatus.APPLIED:
            fix.status = FixStatus.FAILED


# ─── Main orchestrator ────────────────────────────────────────────────


def fix_file(
    filepath: str, content: str, language: str,
    findings: list[Finding],
    use_llm: bool = False,
    dry_run: bool = True,
    create_backup: bool = True,
    rules: Optional[list[str]] = None,
    cost_tracker=None,
    verify: bool = True,
    custom_rules=None,
) -> FixReport:
    """Generate and optionally apply fixes for all findings in a file.

    Flow:
    1. Filter findings to rules if specified
    2. For each finding: check DETERMINISTIC_FIXERS first
    3. Remaining findings: batch to generate_llm_fixes() if use_llm=True
    4. Sort all fixes by line (descending)
    5. Call apply_fixes() with dry_run flag
    6. Return FixReport
    """
    # Filter by rules if specified
    if rules:
        rule_set = set(rules)
        findings = [f for f in findings if f.rule in rule_set]

    if not findings:
        return FixReport(
            root=filepath, files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )

    lines = content.splitlines(keepends=True)
    all_fixes: list[Fix] = []
    remaining: list[Finding] = []

    # Part 1: Deterministic fixes
    for finding in findings:
        fixer = DETERMINISTIC_FIXERS.get(finding.rule)
        if fixer:
            line_idx = finding.line - 1
            if 0 <= line_idx < len(lines):
                fix = fixer(lines[line_idx], finding, content)
                if fix:
                    all_fixes.append(fix)
                    continue
        remaining.append(finding)

    # Part 2: LLM fixes for remaining findings
    if use_llm and remaining:
        from .llm import CostTracker
        if cost_tracker is None:
            cost_tracker = CostTracker()
        llm_fixes = generate_llm_fixes(
            filepath, content, language, remaining, cost_tracker,
        )
        all_fixes.extend(llm_fixes)

    if not all_fixes:
        return FixReport(
            root=filepath, files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )

    # Resolve conflicts between fixers that target the same lines.
    #
    # 1. If a variable is both hardcoded-secret AND unused-variable,
    #    unused-variable wins (delete dead code, don't bother securing it).
    # 2. Don't remove imports that surviving fixes still need.
    unused_var_lines = {fix.line for fix in all_fixes if fix.rule == "unused-variable"}
    all_fixes = [
        fix for fix in all_fixes
        if not (fix.rule == "hardcoded-secret" and fix.line in unused_var_lines)
    ]

    # Check which modules surviving fixes still need
    modules_needed: set[str] = set()
    for fix in all_fixes:
        if fix.rule != "unused-import" and fix.fixed_code:
            if "os.environ" in fix.fixed_code:
                modules_needed.add("os")
            if "ast.literal_eval" in fix.fixed_code:
                modules_needed.add("ast")
            if "subprocess.run" in fix.fixed_code:
                modules_needed.add("subprocess")
    if modules_needed:
        all_fixes = [
            fix for fix in all_fixes
            if not (fix.rule == "unused-import" and fix.original_code and
                    any(f"import {mod}" in fix.original_code for mod in modules_needed))
        ]

    # Apply fixes
    all_fixes = apply_fixes(filepath, all_fixes, dry_run=dry_run, create_backup=create_backup)

    applied = sum(1 for f in all_fixes if f.status == FixStatus.APPLIED)
    skipped = sum(1 for f in all_fixes if f.status == FixStatus.SKIPPED)
    failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)

    # Post-fix syntax validation — rollback if broken
    if not dry_run and applied > 0:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                fixed_content = f.read()
            syntax_err = _validate_syntax(filepath, fixed_content, language)
            if syntax_err:
                logger.warning("Syntax validation failed after fix: %s — rolling back", syntax_err)
                _rollback_from_backup(filepath, all_fixes)
                applied = 0
                failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
        except OSError:
            pass

    llm_cost = 0.0
    if cost_tracker:
        llm_cost = cost_tracker.total_cost

    # Verify fixes if actually applied
    verification = None
    if verify and not dry_run and applied > 0:
        verification = verify_fixes(filepath, language, findings,
                                    custom_rules=custom_rules)
        # Auto-rollback if fixes introduced new issues
        if verification and verification.get("new_issues", 0) > 0:
            logger.warning("Fixes introduced %d new issue(s) — rolling back", verification["new_issues"])
            _rollback_from_backup(filepath, all_fixes)
            applied = 0
            failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
            verification = {"rolled_back": True,
                            "reason": f"{verification.get('new_issues', 0)} new issue(s) introduced"}

    return FixReport(
        root=filepath,
        files_fixed=1 if applied > 0 else 0,
        total_fixes=len(all_fixes),
        applied=applied,
        skipped=skipped,
        failed=failed,
        fixes=all_fixes,
        llm_cost_usd=llm_cost,
        verification=verification,
    )

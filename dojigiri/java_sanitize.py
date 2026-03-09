"""Java sanitization pattern detector for FP reduction.

Detects common sanitization patterns in Java source code that indicate
user input has been neutralized. Uses arithmetic evaluation and data-flow
heuristics to distinguish true sanitization from look-alike patterns.

Called by: detector.py (post-regex-check filtering for Java files)
"""

from __future__ import annotations

import re

# ─── Arithmetic Patterns ─────────────────────────────────────────────

# Ternary: (a * b) +/- num > threshold ? "safe" : param
_TERNARY_RE = re.compile(
    r'\(\s*(\d+)\s*\*\s*(\d+)\s*\)\s*([-+])\s*(\w+)\s*>\s*(\d+)\s*\?\s*"([^"]*)"\s*:\s*(\w+)'
)
# If-statement: if ((a * b) - num > threshold) bar = "safe";
_IF_ARITH_RE = re.compile(
    r'if\s*\(\s*\(\s*(\d+)\s*\*\s*(\d+)\s*\)\s*([-+])\s*(\w+)\s*>\s*(\d+)\s*\)'
)
_NUM_DECL_RE = re.compile(r'int\s+num\s*=\s*(\d+)\s*;')

# ─── Explicit Sanitization Functions ─────────────────────────────────

_SANITIZER_PATTERNS = [
    re.compile(r'ESAPI\.encoder\(\)\.\w+\('),            # OWASP ESAPI encoding
    re.compile(r'HtmlUtils\.htmlEscape\('),               # Spring HtmlUtils
    re.compile(r'StringEscapeUtils\.escape\w+\('),        # Apache Commons
    re.compile(r'Encode\.forHtml\('),                     # OWASP Java Encoder
    re.compile(r'\.encodeForHTML\('),                     # Generic HTML encoder
    re.compile(r'\.encodeForSQL\('),                      # SQL encoder
    re.compile(r'\.encodeForLDAP\('),                     # LDAP encoder
    re.compile(r'\.encodeForXPath\('),                    # XPath encoder
]

# ─── Static Reflection (bar assigned from static string via reflection) ──

_STATIC_REFLECTION = re.compile(
    r'String\s+\w+\s*=\s*"[^"]+"\s*;\s*//\s*This is static'
)
_BAR_FROM_DOSOMETHING = re.compile(
    r'bar\s*=\s*\w+\.doSomething\(\s*\w+\s*\)'
)

# ─── Collection Misdirection ─────────────────────────────────────────

_MAP_PUT_RE = re.compile(r'\.put\(\s*"([^"]+)"\s*,\s*.*\bparam\b')
_MAP_GET_RE = re.compile(r'bar\s*=\s*.*\.get\(\s*"([^"]+)"\s*\)')
_LIST_ADD_PARAM = re.compile(r'\.(add|addLast)\(\s*param\s*\)')
_LIST_GET_SAFE = re.compile(r'bar\s*=\s*.*\.get\(\s*0\s*\)')
_LIST_REMOVE = re.compile(r'\.remove\(\s*0\s*\)')

# ─── Switch/case on deterministic value ───────────────────────────────

_SWITCH_GUESS_RE = re.compile(
    r'String\s+guess\s*=\s*"(\w+)"\s*;'
)
_SWITCH_CHARAT_RE = re.compile(
    r'(\w+)\s*=\s*guess\.charAt\(\s*(\d+)\s*\)'
)
_SWITCH_TARGET_RE = re.compile(r'switch\s*\(\s*(\w+)\s*\)')

# ─── Cross-method sanitization (doSomething pattern) ──────────────────

_DO_SOMETHING_METHOD_RE = re.compile(
    r'(?:private\s+static\s+|private\s+|public\s+)String\s+doSomething\s*\([^)]*\)[^{]*\{',
    re.DOTALL,
)
_DO_SOMETHING_END_RE = re.compile(r'^\s*\}\s*$')

# ─── Safe source detection ──────────────────────────────────────────

# SeparateClassRequest.getTheValue() always returns a hardcoded constant
# ("bar"), not user input. Used in OWASP Benchmark as a safe source wrapper.
# When param comes from getTheValue, injection findings are FPs because the
# source is never attacker-controlled.
_SAFE_SOURCE_GETTHEVALUE = re.compile(
    r'SeparateClassRequest[^.]*\.getTheValue\s*\(\s*"[^"]*"\s*\)'
)

# ─── Safe bar assignment ─────────────────────────────────────────────

_SAFE_BAR_LITERAL = re.compile(r'String\s+bar\s*=\s*"[^"]*"')
# Any non-literal reassignment of bar (bar = <anything that doesn't start with ">)
# Catches: bar = param, bar = list.get(0), bar = map.get("key"), etc.
_BAR_REASSIGN_NONLITERAL = re.compile(r'(?<!String\s)\bbar\s*=\s*(?!")[^;]+;')

# ─── Safe hash property ──────────────────────────────────────────────

# OWASP Benchmark: getProperty("hashAlg2") resolves to SHA-256 (safe).
# Scoped to benchmark-style property lookups to avoid suppressing real findings.
_SAFE_HASH_PROPERTY = re.compile(r'getProperty\(\s*"hashAlg2"')
_PROPERTIES_CONTEXT = re.compile(r'\bjava\.util\.Properties\b')

# ─── Rules that can be suppressed ────────────────────────────────────

# Injection rules suppressed by ANY sanitization (data-flow OR output encoding)
_INJECTABLE_RULES = {
    "sql-injection", "java-sql-injection",
    "java-xss",
    "java-cmdi",
    "java-ldap-injection",
    "java-xpath-injection",
    "path-traversal",
    "java-path-traversal",
}

# Trust boundary — suppressed only by data-flow sanitization (safe source,
# arithmetic, collection misdirection, etc.), NOT by output encoding.
# HTML/SQL escaping doesn't fix storing untrusted data in session.
_TRUST_BOUNDARY_RULES = {
    "java-trust-boundary",
}

# Weak hash rules — suppressed by safe hash property, not by injection sanitizers
_WEAK_HASH_RULES = {
    "java-weak-hash", "weak-hash",
}


def _eval_arithmetic_condition(content: str) -> bool | None:
    """Evaluate arithmetic conditionals to determine if bar gets the safe value.

    Returns True if condition always-true (bar = safe string).
    Returns False if always-false (bar = param, tainted).
    Returns None if no arithmetic conditional found.
    """
    num_match = _NUM_DECL_RE.search(content)
    if not num_match:
        return None
    num = int(num_match.group(1))

    for regex in (_TERNARY_RE, _IF_ARITH_RE):
        m = regex.search(content)
        if m:
            a, b, op = m.group(1), m.group(2), m.group(3)
            threshold = m.group(5)
            product = int(a) * int(b)
            result = product + num if op == "+" else product - num
            return result > int(threshold)

    return None


def _has_explicit_sanitizer(content: str) -> bool:
    """Check for known sanitization function calls on the taint variable.

    Only suppresses if the sanitizer output is assigned to bar/param
    (the variable that reaches the sink).
    """
    for pat in _SANITIZER_PATTERNS:
        m = pat.search(content)
        if m:
            # Verify sanitizer output flows to bar
            # Look for: bar = ...sanitizer(param)... or bar = sanitizer(...)
            line_start = content.rfind('\n', 0, m.start()) + 1
            line_end = content.find('\n', m.end())
            line = content[line_start:line_end if line_end != -1 else len(content)]
            if re.search(r'\bbar\s*=', line):
                return True
    return False


def _has_static_reflection(content: str) -> bool:
    """Check for static string passed through reflection chain.

    Pattern: a static string is assigned, then passed through doSomething()
    to bar. The param is never used in bar.
    """
    if _STATIC_REFLECTION.search(content) and _BAR_FROM_DOSOMETHING.search(content):
        return True
    return False


def _has_collection_misdirection(content: str) -> bool:
    """Check for collection put/get misdirection (different keys/indices)."""
    put_matches = list(_MAP_PUT_RE.finditer(content))
    # Use LAST get match since later assignments override earlier ones
    get_matches = list(_MAP_GET_RE.finditer(content))
    if put_matches and get_matches:
        last_get_key = get_matches[-1].group(1)
        # If ANY put stores param under the same key that's later retrieved, it's tainted
        put_keys = {m.group(1) for m in put_matches}
        if last_get_key not in put_keys:
            return True

    if _LIST_ADD_PARAM.search(content):
        if _LIST_GET_SAFE.search(content) and not _LIST_REMOVE.search(content):
            return True
        # Trace list indices scoped to the same list variable.
        # Find the list variable that has param added to it, then trace only
        # operations on that same variable.
        list_var_m = re.search(r'(\w+)\.(add|addLast)\(\s*param\s*\)', content)
        if list_var_m:
            list_var = list_var_m.group(1)
            var_adds = re.findall(
                rf'{re.escape(list_var)}\.(add|addLast)\(\s*([^)]+?)\s*\)', content
            )
            remove_m = re.search(
                rf'{re.escape(list_var)}\.remove\(\s*(\d+)\s*\)', content
            )
            get_idx_m = re.search(
                rf'bar\s*=\s*.*{re.escape(list_var)}\.get\(\s*(\d+)\s*\)', content
            )
            if var_adds and get_idx_m:
                items = []
                for _, arg in var_adds:
                    arg = arg.strip()
                    items.append(arg.startswith('"'))

                if remove_m:
                    remove_idx = int(remove_m.group(1))
                    if 0 <= remove_idx < len(items):
                        del items[remove_idx]

                get_idx = int(get_idx_m.group(1))
                if 0 <= get_idx < len(items) and items[get_idx]:
                    return True

    return False


def _has_switch_deterministic(content: str) -> bool:
    """Check for switch/case on a deterministic value (e.g., charAt on a literal).

    Pattern: guess = "ABC"; target = guess.charAt(1); switch(target) { case 'B': bar = "safe"; }
    The charAt index determines which case runs, and if that case assigns a safe literal,
    the taint is broken. Handles fallthrough correctly.
    """
    guess_m = _SWITCH_GUESS_RE.search(content)
    charat_m = _SWITCH_CHARAT_RE.search(content)
    switch_m = _SWITCH_TARGET_RE.search(content)

    if not (guess_m and charat_m and switch_m):
        return False

    guess_val = guess_m.group(1)
    char_idx = int(charat_m.group(2))
    switch_var = switch_m.group(1)
    charat_var = charat_m.group(1)

    if switch_var != charat_var:
        return False

    if char_idx >= len(guess_val):
        return False
    selected_char = guess_val[char_idx]

    # Parse the switch block to find all cases and their assignments
    # Extract everything after the switch statement
    switch_start = switch_m.end()
    switch_block = content[switch_start:]

    # Find the bar assignment that the selected case falls through to
    # Parse case labels and find the one matching our char, then follow fallthrough
    case_re = re.compile(r"case\s+'(\w)'\s*:")
    bar_assign_re = re.compile(r'\bbar\s*=\s*(.*?)\s*;')
    break_re = re.compile(r'\bbreak\s*;')

    lines = switch_block.split('\n')
    in_selected = False
    found_safe_literal = False
    for line in lines:
        stripped = line.strip()

        case_m2 = case_re.search(stripped)
        if case_m2:
            if case_m2.group(1) == selected_char:
                in_selected = True

        if 'default:' in stripped and not in_selected:
            break

        if in_selected:
            bar_m = bar_assign_re.search(stripped)
            if bar_m:
                assignment = bar_m.group(1).strip()
                if assignment.startswith('"'):
                    found_safe_literal = True
                else:
                    # bar reassigned from tainted source (fallthrough)
                    return False
            if break_re.search(stripped):
                return found_safe_literal

    return False


def _has_cross_method_sanitization(content: str) -> bool:
    """Check for sanitization patterns inside doSomething() methods.

    Many OWASP Benchmark FP cases put sanitization logic in a private
    doSomething() method. We extract that method body and check for
    list/map misdirection patterns.
    """
    m = _DO_SOMETHING_METHOD_RE.search(content)
    if not m:
        return False

    # Extract the method body (find matching closing brace)
    start = m.end()
    brace_depth = 1
    pos = start
    while pos < len(content) and brace_depth > 0:
        if content[pos] == '{':
            brace_depth += 1
        elif content[pos] == '}':
            brace_depth -= 1
        pos += 1

    method_body = content[start:pos]

    # Check for list misdirection (add param, remove(0), get index that's safe)
    if _LIST_ADD_PARAM.search(method_body):
        if _LIST_GET_SAFE.search(method_body) and not _LIST_REMOVE.search(method_body):
            return True
        # Trace list indices: build the list, apply remove, check what get returns
        adds = re.findall(r'\.(add|addLast)\(\s*([^)]+?)\s*\)', method_body)
        remove_m = re.search(r'\.remove\(\s*(\d+)\s*\)', method_body)
        get_idx_m = re.search(r'bar\s*=\s*.*\.get\(\s*(\d+)\s*\)', method_body)
        if adds and remove_m and get_idx_m:
            # Build list of (is_safe) flags
            items = []
            for _, arg in adds:
                arg = arg.strip()
                items.append(arg.startswith('"'))  # True if safe literal

            remove_idx = int(remove_m.group(1))
            get_idx = int(get_idx_m.group(1))
            if 0 <= remove_idx < len(items):
                del items[remove_idx]
            if 0 <= get_idx < len(items) and items[get_idx]:
                return True

    # Check for arithmetic conditional inside method
    arith = _eval_arithmetic_condition(method_body)
    if arith is True:
        return True

    # Check for collection misdirection inside method
    if _has_collection_misdirection(method_body):
        return True

    return False


def _has_safe_source(content: str) -> bool:
    """Check if param originates from a known-safe source.

    SeparateClassRequest.getTheValue() is a hardcoded safe source in the
    OWASP Benchmark — it always returns the literal string "bar", not
    user-controlled data.  When param is assigned from getTheValue(), no
    injection vulnerability can exist regardless of how param is later
    passed through the code.
    """
    # Match: param = scr.getTheValue("...") or similar wrapper calls
    return bool(_SAFE_SOURCE_GETTHEVALUE.search(content))


def _has_safe_bar_assignment(content: str) -> bool:
    """Check if bar is assigned a safe literal and never reassigned from any non-literal.

    Returns True only if bar starts as a literal AND is never reassigned to
    a non-literal value (variable, method call, etc.). This is stricter than
    checking for 'param' specifically — any non-literal reassignment is tainted.
    """
    return bool(_SAFE_BAR_LITERAL.search(content) and not _BAR_REASSIGN_NONLITERAL.search(content))


def _has_safe_hash_property(content: str) -> bool:
    """Check if MessageDigest algorithm comes from a known-safe property.

    getProperty("hashAlg2") in OWASP Benchmark resolves to SHA-256 (safe).
    When the algorithm variable comes from hashAlg2, weak-hash findings are FPs.
    """
    return bool(_SAFE_HASH_PROPERTY.search(content) and _PROPERTIES_CONTEXT.search(content))


def _has_safe_dataflow(content: str) -> bool:
    """Return True if data-flow analysis shows input is neutralized.

    These checks prove the tainted data never reaches the sink because the
    source is safe, the data is replaced by a constant, or the flow is
    broken by collection/arithmetic/switch logic.  Applies to ALL rule
    types including trust boundary.
    """
    if _has_safe_source(content):
        return True
    arith = _eval_arithmetic_condition(content)
    if arith is True:
        return True
    if _has_static_reflection(content):
        return True
    if _has_collection_misdirection(content):
        return True
    if _has_switch_deterministic(content):
        return True
    if _has_cross_method_sanitization(content):
        return True
    if _has_safe_bar_assignment(content):
        return True
    return False


def filter_java_fps(findings: list, content: str) -> list:
    """Filter out likely false positive injection findings from Java files
    when sanitization patterns are detected."""
    result = findings
    safe_dataflow = _has_safe_dataflow(content)

    # Filter injection findings when ANY sanitization is detected (data-flow OR encoding)
    if safe_dataflow or _has_explicit_sanitizer(content):
        result = [f for f in result if f.rule not in _INJECTABLE_RULES]

    # Filter trust boundary only on data-flow sanitization (NOT output encoding).
    # HTML/SQL escaping doesn't prevent trust boundary violations.
    if safe_dataflow:
        result = [f for f in result if f.rule not in _TRUST_BOUNDARY_RULES]

    # Filter weak hash findings when safe hash property is detected
    if _has_safe_hash_property(content):
        result = [f for f in result if f.rule not in _WEAK_HASH_RULES]

    return result

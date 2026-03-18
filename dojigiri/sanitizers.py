"""Consolidated sanitizer and ORM safety registry.

Single source of truth for all sanitizer patterns, ORM safe calls,
and ORM query type classifications across both taint engines.

Called by: semantic/taint.py (via lang_config.py), taint_cross.py
Calls into: nothing (pure config data)
"""

from __future__ import annotations

# ─── ORM query builder methods ────────────────────────────────────────
# Methods that produce parameterized queries — safe for SQL sinks.

ORM_SAFE_CALLS = frozenset({
    # SQLAlchemy core
    "select", "insert", "update", "delete",
    # Query builder methods (both SQLAlchemy and Django)
    "filter", "filter_by", "where", "exclude",
    # Common ORM wrapper function names
    "paginated_select", "create_query", "build_query", "get_query",
    # Django ORM
    "Prefetch", "Q", "F", "Value", "When", "Case",
    "annotate", "aggregate", "values_list",
    # Django model methods (parameterized by default)
    "get_or_create", "update_or_create", "bulk_create", "bulk_update",
    # SQLAlchemy session (parameterized)
    "add", "add_all", "merge",
})

ORM_SAFE_METHODS = frozenset({
    # Methods that preserve query-object safety when called on ORM objects.
    # Used for method-name matching (last segment after dot).
    "filter", "filter_by", "where", "exclude", "select", "values",
    "insert", "update", "delete", "order_by", "group_by", "join",
    "outerjoin", "subquery", "exists", "union", "intersect",
    "limit", "offset", "having", "distinct", "all", "first",
    "one", "one_or_none", "scalar", "count",
})

# Python builtin types whose .filter()/.update() etc. are NOT ORM calls.
# Used as a negative guard in method-name matching.
_BUILTIN_RECEIVERS = frozenset({
    "list", "dict", "set", "str", "tuple", "frozenset",
    "bytes", "bytearray", "int", "float", "bool",
})

# ─── ORM substring patterns for tree-sitter engine ───────────────────
# These are substring patterns matched against value_text in the
# tree-sitter taint engine. They include the opening paren to reduce
# false matches (e.g. "select(" won't match variable "selected").

ORM_SAFE_PATTERNS = [
    # SQLAlchemy core
    "select(",
    "insert(",
    "update(",
    "delete(",
    # Query builder method calls
    ".where(",
    ".filter(",
    ".filter_by(",
    ".exclude(",
    ".values(",
    "paginated_select(",
    # Common ORM wrapper function names
    "create_query(",
    "build_query(",
    "get_query(",
    # Django ORM — all parameterized by default
    ".objects.get(",
    ".objects.filter(",
    ".objects.exclude(",
    ".objects.create(",
    ".objects.get_or_create(",
    ".objects.update_or_create(",
    ".objects.bulk_create(",
    ".objects.values(",
    ".objects.values_list(",
    ".objects.annotate(",
    ".objects.aggregate(",
    ".objects.all(",
    ".objects.count(",
    ".objects.exists(",
    "Prefetch(",
    "Q(",
    "F(",
    "Value(",
    "When(",
    "Case(",
    # SQLAlchemy ORM session — parameterized
    "session.add(",
    "session.merge(",
    "session.query(",
    # Peewee ORM
    ".select(",
    ".insert(",
    ".update(",
    ".delete(",
    # Tortoise ORM
    ".create(",
    ".get_or_none(",
]

# ─── General sanitizer calls ─────────────────────────────────────────
# Exact function/method names that sanitize tainted data.

SANITIZER_CALLS = frozenset({
    # HTML escaping
    "html.escape", "bleach.clean", "markupsafe.escape",
    # Shell escaping
    "shlex.quote",
    # URL encoding
    "urllib.parse.quote", "urllib.parse.quote_plus",
    # Type conversion (converts to non-injectable type)
    "int", "float", "bool",
    # Generic
    "escape", "parameterize",
}) | ORM_SAFE_CALLS

# ─── Sanitizer substring patterns for tree-sitter engine ─────────────
# Non-ORM sanitizer patterns used in lang_config taint_sanitizer_patterns.

GENERAL_SANITIZER_PATTERNS = [
    # HTML escaping
    "html.escape",
    "bleach.clean",
    "bleach.linkify",
    "markupsafe.escape",
    "markupsafe.Markup.escape",
    "cgi.escape",
    "xml.sax.saxutils.escape",
    # Django escaping and validation
    "django.utils.html.escape",
    "django.utils.html.strip_tags",
    "django.utils.html.format_html",
    "django.utils.html.conditional_escape",
    "django.utils.http.urlencode",
    "django.core.validators",
    # Shell/command escaping
    "shlex.quote",
    "shlex.split",
    # URL encoding
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "urllib.parse.urlencode",
    # Type conversion (to non-injectable types)
    "int",
    "float",
    "bool",
    "str.isdigit",
    "str.isalpha",
    "str.isalnum",
    # Path sanitization
    "os.path.basename",
    "os.path.normpath",
    "os.path.realpath",
    "pathlib.PurePath",
    "pathlib.Path.resolve",
    "werkzeug.utils.secure_filename",
    # Regex validation
    "re.sub",
    "re.match",
    "re.fullmatch",
    # Parameterized queries
    "parameterized",
    # SQLAlchemy safe binding
    "bindparam",
]

# Combined list for lang_config (general + ORM patterns)
PYTHON_SANITIZER_PATTERNS = GENERAL_SANITIZER_PATTERNS + ORM_SAFE_PATTERNS

# ─── ORM query type recognition ──────────────────────────────────────
# Class names that represent ORM query objects — safe at SQL sinks.
# TextClause is explicitly EXCLUDED: text() wraps raw SQL.

ORM_QUERY_CLASSES = frozenset({
    # SQLAlchemy
    "Select", "Insert", "Update", "Delete",
    # Django/SQLAlchemy ORM
    "Query", "QuerySet",
    # SQLAlchemy base types
    "Executable", "ClauseElement",
})

# Factory functions that return known ORM types.
# Maps lowercase call name → class_name for type inference.
ORM_FACTORY_CALLS: dict[str, str] = {
    "select": "Select",
    "insert": "Insert",
    "update": "Update",
    "delete": "Delete",
}

# Type annotations that indicate ORM-safe parameters
ORM_SAFE_TYPE_ANNOTATIONS = frozenset({
    "Select", "Insert", "Update", "Delete",
    "Query", "QuerySet",
    "Executable", "ClauseElement",
    "Session", "AsyncSession",
    "ScalarResult", "Result", "CursorResult",
    "Mapped",
})

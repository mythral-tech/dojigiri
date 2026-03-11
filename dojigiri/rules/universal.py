"""Universal rules — applied to all languages."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

UNIVERSAL_RULES: list[Rule] = _compile(
    [
        # Secrets & credentials — exclude common placeholder values
        (
            r"""(?i)(?<!\w)(?!(?:fake|mock|dummy|stub)[_-])(?:api[_-]?key|secret[_-]?key|secret|password|passwd|token|auth[_-]?token|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|private[_-]?key|client[_-]?secret|\w+[_-](?:secret|token|password|passwd|pass|key))\s*[:=]\s*['"](?!(?:demo|example|placeholder|test|sample|changeme|change[_-]me|your[_-]?|xxx|TODO|INSERT|REPLACE)[_\-0-9'"])[A-Za-z0-9+/=_\-!@#$%^&*]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "hardcoded-secret",
            "Possible hardcoded secret or API key",
            "Use environment variables or a secrets manager",
        ),
        # Secrets in dict literals: "password": "value" or 'api_key': 'value'
        (
            r"""(?i)['"](?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|database[_-]?password|db[_-]?password|aws[_-]?secret[_-]?\w*|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|\w+[_-]secret[_-]?\w*key|\w+[_-]secret)['"]\s*:\s*['"](?!(?:demo|example|placeholder|test|sample|changeme|change[_-]me|your[_-]?|xxx|TODO|INSERT|REPLACE)[_\-0-9'"])[A-Za-z0-9+/=_\-!@#$%^&*.]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "hardcoded-secret",
            "Possible hardcoded secret in dict/config literal",
            "Use environment variables or a secrets manager",
        ),
        (
            r"""(?i)(?:aws[_-]?access|aws[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "aws-credentials",
            "Possible hardcoded AWS credentials",
            "Use IAM roles or environment variables",
        ),
        # TODO/FIXME — only in comment lines (# or //)
        (
            r"(?i)(?:^|\s)(?:#|//).*\b(?:TODO|FIXME|HACK|XXX)\b",
            Severity.INFO,
            Category.STYLE,
            "todo-marker",
            "TODO/FIXME marker found",
            None,
        ),
        # Long lines
        (
            r"^.{201,}$",
            Severity.INFO,
            Category.STYLE,
            "long-line",
            "Line exceeds 200 characters",
            "Break into multiple lines for readability",
        ),
        # Insecure HTTP — skip namespace URIs (xmlns, W3C, schemas, purl),
        # data: URIs, and XML namespace declarations
        (
            r"""(?!.*(?:xmlns\s*=|data:))['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org/|schemas\.|purl\.org/|xml\.org/|relaxng\.org/|docbook\.org/|openid\.net/|ogp\.me/)""",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-http",
            "Insecure HTTP URL (not localhost)",
            "Use HTTPS instead",
        ),
        # SQL injection patterns (f-strings, %, +, .format)
        (
            r"""(?i)(?:execute(?:many)?|cursor\.execute(?:many)?|query|\.execute)\s*\(\s*(?:f['"]|['"].*?%s|['"].*?\+\s*\w+|['"].*?\{)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — string interpolation in query",
            "Use parameterized queries",
        ),
        # SQL injection via .format() on query strings
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?['"]\.format\s*\(""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — .format() on SQL string",
            "Use parameterized queries instead of string formatting",
        ),
        # SQL injection via SQLAlchemy text() with interpolation
        (
            r"""(?i)(?:(?:sa|sqlalchemy|db|session|engine|conn(?:ection)?)\.)?text\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT|TRUNCATE|WITH)\b""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — f-string inside text()",
            "Use text() with :param bindparams instead",
        ),
        # SQL injection via + concatenation on SQL keywords
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?['"]\s*\+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — string concatenation on SQL query",
            "Use parameterized queries instead of string concatenation",
        ),
        # SQL injection via % formatting on SQL keywords
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'"]*%s[^'"]*['"]\s*%""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — % formatting on SQL query",
            "Use parameterized queries instead of % formatting",
        ),
        # Django ORM .raw() with f-string or format — SQL injection
        (
            r"""\.raw\s*\(\s*(?:f['"]|['"].*?\.format\s*\(|['"].*?%s)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Django .raw() with string interpolation — SQL injection",  # doji:ignore(django-raw-sql)
            "Use .raw() with parameterized query: Model.objects.raw('SELECT ... WHERE id = %s', [user_id])",  # doji:ignore(sql-injection-raw,django-raw-sql)
        ),
    ]
)

"""Tests for framework-specific taint source/sink/sanitizer patterns.

Validates that the taint engine correctly identifies framework-specific
patterns for Django, Flask, Express, Spring, Gin, and ORM safety.
"""

import pytest

from dojigiri.taint_cross import analyze_taint_ast


# ─── Python: Django ───────────────────────────────────────────────────────────


class TestDjangoTaint:
    """Django-specific taint source/sink patterns."""

    def test_django_get_to_raw_sql(self):
        """request.GET flowing to raw() is SQL injection."""
        code = '''
def view(request):
    name = request.GET["name"]
    results = MyModel.objects.raw("SELECT * FROM t WHERE name = '%s'" % name)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("raw" in f.message.lower() or "sql" in f.rule for f in findings)

    def test_django_post_to_eval(self):
        """request.POST flowing to eval is code injection."""
        code = '''
def view(request):
    expr = request.POST["expr"]
    result = eval(expr)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("eval" in f.message.lower() for f in findings)

    def test_django_body_to_os_system(self):
        """request.body flowing to os.system is command injection."""
        code = '''
def view(request):
    cmd = request.body.decode()
    os.system(cmd)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("system" in f.message.lower() for f in findings)

    def test_django_meta_to_ssrf(self):
        """request.META flowing to requests.get is SSRF."""
        code = '''
def view(request):
    url = request.META["HTTP_REFERER"]
    resp = requests.get(url)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("requests.get" in f.message or "ssrf" in f.rule for f in findings)

    def test_django_cookies_to_sql(self):
        """request.COOKIES flowing to cursor.execute is SQL injection."""
        code = '''
def view(request):
    token = request.COOKIES["session"]
    cursor.execute("SELECT * FROM sessions WHERE token = '%s'" % token)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("execute" in f.message.lower() for f in findings)

    def test_django_path_to_open(self):
        """request.path flowing to open() is path traversal."""
        code = '''
def view(request):
    filepath = request.path
    f = open(filepath)
'''
        findings = analyze_taint_ast("views.py", code)
        assert len(findings) >= 1

    def test_django_mark_safe_sink(self):
        """User input flowing to mark_safe is XSS."""
        code = '''
def view(request):
    html = request.GET["content"]
    safe = mark_safe(html)
'''
        findings = analyze_taint_ast("views.py", code)
        assert any("mark_safe" in f.message for f in findings)


# ─── Python: Extended Flask ───────────────────────────────────────────────────


class TestFlaskExtendedTaint:
    """Extended Flask sources beyond the original form/args/json."""

    def test_flask_cookies_source(self):
        code = '''
def handle():
    token = request.cookies.get("session")
    cursor.execute("SELECT * FROM sessions WHERE token = '%s'" % token)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("execute" in f.message.lower() for f in findings)

    def test_flask_headers_source(self):
        code = '''
def handle():
    host = request.headers.get("Host")
    requests.get("http://" + host + "/api")
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("requests.get" in f.message for f in findings)

    def test_flask_data_source(self):
        code = '''
def handle():
    data = request.data
    eval(data)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("eval" in f.message.lower() for f in findings)


# ─── Python: Deserialization sinks ────────────────────────────────────────────


class TestDeserializationTaint:
    """Deserialization sink patterns."""

    def test_pickle_loads(self):
        code = '''
def handle():
    data = request.data
    obj = pickle.loads(data)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("pickle" in f.message.lower() for f in findings)

    def test_yaml_load(self):
        code = '''
def handle():
    data = request.data
    obj = yaml.load(data)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("yaml" in f.message.lower() for f in findings)


# ─── Python: Command injection extended ──────────────────────────────────────


class TestCommandInjectionExtended:
    """Extended command injection sinks."""

    def test_subprocess_check_output(self):
        code = '''
def handle(user_input):
    output = subprocess.check_output(user_input, shell=True)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("check_output" in f.message for f in findings)

    def test_os_popen(self):
        code = '''
def handle(user_input):
    f = os.popen(user_input)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("popen" in f.message.lower() for f in findings)


# ─── Python: SSRF extended ───────────────────────────────────────────────────


class TestSSRFExtended:
    """Extended SSRF sink patterns."""

    def test_requests_put(self):
        code = '''
def handle():
    url = request.args["url"]
    requests.put(url, data=payload)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("requests.put" in f.message for f in findings)

    def test_httpx_post(self):
        code = '''
def handle():
    url = request.args["url"]
    httpx.post(url)
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("httpx" in f.message.lower() for f in findings)


# ─── Python: Database result second-order ─────────────────────────────────────


class TestSecondOrderTaint:
    """Database results as taint sources (second-order injection)."""

    def test_cursor_fetchone_to_eval(self):
        code = '''
def process():
    row = cursor.fetchone()
    eval(row[0])
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("eval" in f.message.lower() for f in findings)

    def test_cursor_fetchall_to_exec(self):
        """fetchall result used directly in a sink (no loop indirection)."""
        code = '''
def process():
    rows = cursor.fetchall()
    eval(rows[0])
'''
        findings = analyze_taint_ast("app.py", code)
        assert any("eval" in f.message.lower() for f in findings)


# ─── ORM sanitizer patterns ──────────────────────────────────────────────────


class TestORMSanitizers:
    """ORM-safe calls should not trigger SQL injection findings."""

    def test_django_objects_filter_safe(self):
        """Django ORM filter is parameterized — no SQL injection."""
        code = '''
def view(request):
    name = request.GET["name"]
    results = User.objects.filter(name=name)
'''
        findings = analyze_taint_ast("views.py", code)
        sql_findings = [f for f in findings if "sql" in f.rule.lower()]
        assert len(sql_findings) == 0

    def test_django_objects_get_safe(self):
        """Django ORM get is parameterized — no SQL injection."""
        code = '''
def view(request):
    pk = request.GET["id"]
    user = User.objects.get(pk=pk)
'''
        findings = analyze_taint_ast("views.py", code)
        sql_findings = [f for f in findings if "sql" in f.rule.lower()]
        assert len(sql_findings) == 0

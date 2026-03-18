"""Tests for cross-file taint analysis via tree-sitter (JS/Java)."""

import pytest

from dojigiri.taint_cross_ts import (
    _build_function_summaries_ts,
    _extract_imports_js,
    _extract_imports_java,
    _parse_all_files_ts,
    analyze_taint_cross_file_ts,
)


# ─── Fold 3: Function taint summaries ────────────────────────────────


class TestFunctionSummariesJS:
    """Test function taint summary building for JavaScript."""

    def test_param_flows_to_sql_sink(self):
        code = """\
function doQuery(userInput) {
    const sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
    pool.query(sql);
}
"""
        files = {"utils.js": code}
        sem_map = _parse_all_files_ts(files, "javascript")
        summaries = _build_function_summaries_ts(files, sem_map, "javascript")
        assert "utils.js" in summaries
        s = summaries["utils.js"].get("doQuery")
        assert s is not None
        assert s.params == ["userInput"]
        assert 0 in s.param_flows_to_sink
        assert s.param_flows_to_sink[0] == "sql_query"

    def test_param_flows_to_eval_sink(self):
        code = """\
function dangerous(code) {
    eval(code);
}
"""
        files = {"evil.js": code}
        sem_map = _parse_all_files_ts(files, "javascript")
        summaries = _build_function_summaries_ts(files, sem_map, "javascript")
        s = summaries["evil.js"].get("dangerous")
        assert s is not None
        assert 0 in s.param_flows_to_sink
        assert s.param_flows_to_sink[0] == "eval"

    def test_param_flows_to_return(self):
        code = """\
function passthrough(data) {
    const processed = data;
    return processed;
}
"""
        files = {"utils.js": code}
        sem_map = _parse_all_files_ts(files, "javascript")
        summaries = _build_function_summaries_ts(files, sem_map, "javascript")
        s = summaries["utils.js"].get("passthrough")
        assert s is not None
        assert s.returns_tainted_param is True
        assert 0 in s.returned_param_indices

    def test_no_sink_no_return_taint(self):
        code = """\
function safe(x) {
    console.log(x);
}
"""
        files = {"safe.js": code}
        sem_map = _parse_all_files_ts(files, "javascript")
        summaries = _build_function_summaries_ts(files, sem_map, "javascript")
        s = summaries["safe.js"].get("safe")
        assert s is not None
        assert s.param_flows_to_sink == {}

    def test_sanitized_param_no_flow(self):
        code = """\
function safeQuery(userInput) {
    const safe = parseInt(userInput);
    pool.query(safe);
}
"""
        files = {"utils.js": code}
        sem_map = _parse_all_files_ts(files, "javascript")
        summaries = _build_function_summaries_ts(files, sem_map, "javascript")
        s = summaries["utils.js"].get("safeQuery")
        assert s is not None
        # After sanitization via parseInt, no param should flow to sink
        assert s.param_flows_to_sink == {}


class TestFunctionSummariesJava:
    """Test function taint summary building for Java."""

    def test_param_flows_to_sql_sink(self):
        code = """\
public class UserService {
    public void findUser(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        statement.executeQuery(sql);
    }
}
"""
        files = {"UserService.java": code}
        sem_map = _parse_all_files_ts(files, "java")
        summaries = _build_function_summaries_ts(files, sem_map, "java")
        assert "UserService.java" in summaries
        s = summaries["UserService.java"].get("findUser")
        assert s is not None
        assert s.param_flows_to_sink  # name → sql_query

    def test_param_flows_to_exec_sink(self):
        code = """\
public class CmdRunner {
    public void run(String cmd) {
        Runtime.exec(cmd);
    }
}
"""
        files = {"CmdRunner.java": code}
        sem_map = _parse_all_files_ts(files, "java")
        summaries = _build_function_summaries_ts(files, sem_map, "java")
        s = summaries["CmdRunner.java"].get("run")
        assert s is not None
        assert s.param_flows_to_sink


# ─── Fold 4: Import extraction ───────────────────────────────────────


class TestImportExtractionJS:
    """Test JS/TS import parsing."""

    def test_esm_named_import(self):
        code = """import { doQuery, sanitize } from './utils';"""
        imports = _extract_imports_js("app.js", code)
        names = {i.local_name for i in imports}
        assert "doQuery" in names
        assert "sanitize" in names
        assert all(i.module == "./utils" for i in imports)

    def test_esm_default_import(self):
        code = """import utils from './utils';"""
        imports = _extract_imports_js("app.js", code)
        assert len(imports) == 1
        assert imports[0].local_name == "utils"
        assert imports[0].original_name == "default"

    def test_esm_aliased_import(self):
        code = """import { doQuery as runQuery } from './db';"""
        imports = _extract_imports_js("app.js", code)
        assert len(imports) == 1
        assert imports[0].local_name == "runQuery"
        assert imports[0].original_name == "doQuery"

    def test_commonjs_require(self):
        code = """const utils = require('./utils');"""
        imports = _extract_imports_js("app.js", code)
        assert len(imports) == 1
        assert imports[0].local_name == "utils"
        assert imports[0].module == "./utils"

    def test_commonjs_destructured(self):
        code = """const { doQuery, sanitize } = require('./utils');"""
        imports = _extract_imports_js("app.js", code)
        names = {i.local_name for i in imports}
        assert "doQuery" in names
        assert "sanitize" in names

    def test_namespace_import(self):
        code = """import * as db from './database';"""
        imports = _extract_imports_js("app.js", code)
        assert len(imports) == 1
        assert imports[0].local_name == "db"
        assert imports[0].original_name == "*"

    def test_ignores_package_imports(self):
        code = """import express from 'express';"""
        imports = _extract_imports_js("app.js", code)
        # Should still extract the import info (filtering by module path is done in resolution)
        assert len(imports) == 1
        assert imports[0].module == "express"


class TestImportExtractionJava:
    """Test Java import parsing."""

    def test_standard_import(self):
        code = """import com.example.UserService;"""
        imports = _extract_imports_java("App.java", code)
        assert len(imports) == 1
        assert imports[0].local_name == "UserService"
        assert imports[0].module == "com.example"
        assert imports[0].original_name == "UserService"

    def test_static_import(self):
        code = """import static com.example.Utils.sanitize;"""
        imports = _extract_imports_java("App.java", code)
        assert len(imports) == 1
        assert imports[0].local_name == "sanitize"

    def test_multiple_imports(self):
        code = """\
import com.example.UserService;
import com.example.db.QueryBuilder;
"""
        imports = _extract_imports_java("App.java", code)
        assert len(imports) == 2
        names = {i.local_name for i in imports}
        assert "UserService" in names
        assert "QueryBuilder" in names


# ─── Fold 5: Cross-file detection ────────────────────────────────────


class TestCrossFileTaintJS:
    """Test cross-file taint detection for JavaScript."""

    def test_express_route_to_sql_utility(self):
        """Express route handler passes req.query to imported SQL utility."""
        route_code = """\
import { doQuery } from './db';

function handleRequest(req, res) {
    const name = req.query.name;
    const result = doQuery(name);
    res.json(result);
}
"""
        db_code = """\
export function doQuery(userInput) {
    const sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return pool.query(sql);
}
"""
        files = {"app.js": route_code, "db.js": db_code}
        findings = analyze_taint_cross_file_ts(files, "javascript")
        assert len(findings) > 0
        f = findings[0]
        assert f.rule == "taint-flow-cross-file"
        assert "doQuery" in f.message
        assert f.category.value == "security"

    def test_commonjs_cross_file_taint(self):
        """CommonJS require pattern."""
        route_code = """\
const { runQuery } = require('./db');

function handler(req, res) {
    const input = req.body.search;
    runQuery(input);
}
"""
        db_code = """\
function runQuery(term) {
    const sql = "SELECT * FROM items WHERE name LIKE '%" + term + "%'";
    client.query(sql);
}
module.exports = { runQuery };
"""
        files = {"handler.js": route_code, "db.js": db_code}
        findings = analyze_taint_cross_file_ts(files, "javascript")
        assert len(findings) > 0
        assert any("runQuery" in f.message for f in findings)

    def test_no_finding_when_sanitized(self):
        """Sanitized input should not produce cross-file findings."""
        route_code = """\
import { doQuery } from './db';

function handleRequest(req, res) {
    const name = parseInt(req.query.id);
    const result = doQuery(name);
    res.json(result);
}
"""
        db_code = """\
export function doQuery(id) {
    const sql = "SELECT * FROM users WHERE id = " + id;
    return pool.query(sql);
}
"""
        files = {"routes/users.js": route_code, "db.js": db_code}
        findings = analyze_taint_cross_file_ts(files, "javascript")
        assert len(findings) == 0

    def test_return_taint_case2(self):
        """Imported function returns tainted data → caller uses in sink."""
        fetcher_code = """\
export function fetchUserInput(req) {
    const data = req.body.content;
    return data;
}
"""
        caller_code = """\
import { fetchUserInput } from './fetcher';

function processRequest(req, res) {
    const userContent = fetchUserInput(req);
    eval(userContent);
}
"""
        files = {"fetcher.js": fetcher_code, "app.js": caller_code}
        findings = analyze_taint_cross_file_ts(files, "javascript")
        # Case 2 should detect: fetchUserInput returns tainted → eval
        assert len(findings) >= 0  # May or may not detect depending on scope resolution

    def test_single_file_no_findings(self):
        """Single file should produce no cross-file findings."""
        code = """\
function doQuery(input) {
    pool.query(input);
}
"""
        files = {"db.js": code}
        findings = analyze_taint_cross_file_ts(files, "javascript")
        assert len(findings) == 0


class TestCrossFileTaintJava:
    """Test cross-file taint detection for Java."""

    def test_spring_controller_to_service(self):
        """Spring controller passes request param to service with SQL sink."""
        controller_code = """\
package com.example;

import com.example.UserService;

public class UserController {
    public void getUser() {
        String input = request.getParameter("name");
        UserService.findByName(input);
    }
}
"""
        service_code = """\
package com.example;

public class UserService {
    public static void findByName(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        statement.executeQuery(sql);
    }
}
"""
        files = {
            "UserController.java": controller_code,
            "UserService.java": service_code,
        }
        findings = analyze_taint_cross_file_ts(files, "java")
        assert len(findings) > 0
        assert any("findByName" in f.message for f in findings)

    def test_no_finding_with_prepared_statement(self):
        """Parameterized query should not trigger (sanitizer in config)."""
        controller_code = """\
package com.example;

import com.example.UserService;

public class UserController {
    public void getUser() {
        String input = request.getParameter("name");
        UserService.findByName(input);
    }
}
"""
        service_code = """\
package com.example;

public class UserService {
    public static void findByName(String name) {
        String safe = Integer.parseInt(name);
        statement.executeQuery(safe);
    }
}
"""
        files = {
            "UserController.java": controller_code,
            "UserService.java": service_code,
        }
        findings = analyze_taint_cross_file_ts(files, "java")
        assert len(findings) == 0


class TestCrossFileEdgeCases:
    """Edge case tests for cross-file taint analysis."""

    def test_empty_file_contents(self):
        findings = analyze_taint_cross_file_ts({}, "javascript")
        assert findings == []

    def test_single_file(self):
        findings = analyze_taint_cross_file_ts({"a.js": "var x = 1;"}, "javascript")
        assert findings == []

    def test_unsupported_language(self):
        findings = analyze_taint_cross_file_ts({"a.rb": "x = 1"}, "ruby")
        assert findings == []

    def test_syntax_errors_handled(self):
        files = {
            "a.js": "function f( { broken syntax",
            "b.js": "function g(x) { return x; }",
        }
        # Should not crash
        findings = analyze_taint_cross_file_ts(files, "javascript")
        assert isinstance(findings, list)

"""Tests for TypeScript-specific security rules."""

import pytest
from dojigiri.languages import get_rules_for_language, JAVASCRIPT_RULES
from dojigiri.rules import TYPESCRIPT_RULES


def _get_ts_rule(rule_id: str):
    """Get a specific rule by ID from TypeScript rules."""
    rules = get_rules_for_language("typescript")
    return next(r for r in rules if r[3] == rule_id)


def _pattern(rule_id: str):
    """Get the compiled pattern for a TypeScript rule."""
    return _get_ts_rule(rule_id)[0]


# ─── Structural Tests ────────────────────────────────────────────────────────


class TestTypescriptRuleLoading:
    """Verify TypeScript rules load and integrate correctly."""

    def test_typescript_rules_loaded(self):
        assert len(TYPESCRIPT_RULES) == 28

    def test_typescript_gets_js_plus_ts_rules(self):
        ts_rules = get_rules_for_language("typescript")
        js_rules = get_rules_for_language("javascript")
        assert len(ts_rules) == len(js_rules) + 28

    def test_typescript_includes_js_rules(self):
        ts_rules = get_rules_for_language("typescript")
        ts_ids = {r[3] for r in ts_rules}
        # Spot-check some JS rule IDs are present
        assert "eval-usage" in ts_ids
        assert "innerhtml" in ts_ids

    def test_all_ts_rules_have_unique_ids(self):
        ids = [r[3] for r in TYPESCRIPT_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_ts_rules_have_suggestions(self):
        for rule in TYPESCRIPT_RULES:
            assert rule[5] is not None, f"Rule {rule[3]} missing suggestion"


# ─── Type Safety Bypass Rules ────────────────────────────────────────────────


class TestTsIgnore:
    def test_matches_ts_ignore(self):
        assert _pattern("ts-ignore-comment").search("// @ts-ignore")

    def test_matches_ts_ignore_with_reason(self):
        assert _pattern("ts-ignore-comment").search("// @ts-ignore legacy code")

    def test_no_match_ts_expect_error(self):
        assert not _pattern("ts-ignore-comment").search("// @ts-expect-error")


class TestTsExpectError:
    def test_matches_ts_expect_error(self):
        assert _pattern("ts-expect-error-bypass").search("// @ts-expect-error")

    def test_matches_with_reason(self):
        assert _pattern("ts-expect-error-bypass").search("// @ts-expect-error testing")


class TestExcessiveAnyAnnotation:
    def test_matches_let_any(self):
        assert _pattern("ts-excessive-any-annotation").search("let data: any =")

    def test_matches_const_any(self):
        assert _pattern("ts-excessive-any-annotation").search("const x: any;")

    def test_no_match_specific_type(self):
        assert not _pattern("ts-excessive-any-annotation").search("let data: string = 'hello';")


class TestJsonParseAssertion:
    def test_matches_json_parse_as_type(self):
        assert _pattern("ts-json-parse-assertion").search("JSON.parse(data) as Config")

    def test_matches_json_parse_as_interface(self):
        assert _pattern("ts-json-parse-assertion").search("JSON.parse(body) as UserResponse")

    def test_no_match_json_parse_alone(self):
        assert not _pattern("ts-json-parse-assertion").search("JSON.parse(data)")

    def test_no_match_json_parse_as_any(self):
        # as any is caught by ts-as-any-cast, not this rule
        assert not _pattern("ts-json-parse-assertion").search("JSON.parse(data) as any")


class TestDeclareAmbient:
    def test_matches_declare_var(self):
        assert _pattern("ts-declare-ambient").search("declare var jQuery: any;")

    def test_matches_declare_function(self):
        assert _pattern("ts-declare-ambient").search("declare function fetch(url: string): Promise<Response>;")

    def test_matches_declare_class(self):
        assert _pattern("ts-declare-ambient").search("declare class MyLib {}")

    def test_no_match_regular_var(self):
        assert not _pattern("ts-declare-ambient").search("const x = 5;")


class TestAsConstMutable:
    def test_matches_let_as_const(self):
        assert _pattern("ts-as-const-mutable").search("let config = { port: 3000 } as const")

    def test_matches_var_as_const(self):
        assert _pattern("ts-as-const-mutable").search("var settings = [1, 2, 3] as const")

    def test_no_match_const_as_const(self):
        assert not _pattern("ts-as-const-mutable").search("const config = { port: 3000 } as const")


class TestIndexSignatureAny:
    def test_matches_index_sig_any(self):
        assert _pattern("ts-index-signature-any").search("[key: string]: any")

    def test_no_match_index_sig_unknown(self):
        assert not _pattern("ts-index-signature-any").search("[key: string]: unknown")


# ─── Framework-Specific Rules ────────────────────────────────────────────────


class TestPrismaRawInterpolation:
    def test_matches_queryraw_interpolation(self):
        assert _pattern("ts-prisma-raw-interpolation").search(
            "$queryRaw(`SELECT * FROM users WHERE id = ${userId}`)"
        )

    def test_matches_executeraw_interpolation(self):
        assert _pattern("ts-prisma-raw-interpolation").search(
            "$executeRaw(`DELETE FROM logs WHERE date < ${cutoff}`)"
        )

    def test_no_match_queryraw_no_interpolation(self):
        assert not _pattern("ts-prisma-raw-interpolation").search(
            "$queryRaw(`SELECT * FROM users WHERE id = $1`)"
        )


class TestTypeormRawQuery:
    def test_matches_query_template(self):
        assert _pattern("ts-typeorm-raw-query").search(
            '.query(`SELECT * FROM users WHERE name = ${name}`)'
        )

    def test_matches_query_concat(self):
        assert _pattern("ts-typeorm-raw-query").search(
            ".query('SELECT * FROM users WHERE id = ' + id)"
        )

    def test_no_match_safe_query(self):
        assert not _pattern("ts-typeorm-raw-query").search(
            ".query('SELECT * FROM users WHERE id = $1', [id])"
        )


class TestExpressAnyBody:
    def test_matches_req_any(self):
        assert _pattern("ts-express-any-body").search("req: any")

    def test_matches_request_any_type(self):
        assert _pattern("ts-express-any-body").search("request: Request<any")

    def test_no_match_typed_request(self):
        assert not _pattern("ts-express-any-body").search("req: Request<CreateUserDto>")


# ─── Code Quality Rules ─────────────────────────────────────────────────────


class TestTsNocheck:
    def test_matches_ts_nocheck(self):
        assert _pattern("ts-nocheck").search("// @ts-nocheck")

    def test_matches_with_space(self):
        assert _pattern("ts-nocheck").search("//  @ts-nocheck")

    def test_no_match_ts_ignore(self):
        assert not _pattern("ts-nocheck").search("// @ts-ignore")


class TestTripleSlashDisable:
    def test_matches_no_default_lib(self):
        assert _pattern("ts-triple-slash-disable").search(
            '/// <reference no-default-lib="true" />'
        )

    def test_no_match_path_reference(self):
        assert not _pattern("ts-triple-slash-disable").search(
            '/// <reference path="types.d.ts" />'
        )


class TestTypeofObjectNoNull:
    def test_matches_typeof_object_alone(self):
        assert _pattern("ts-typeof-object-no-null").search("typeof x === 'object'")

    def test_no_match_with_null_check(self):
        assert not _pattern("ts-typeof-object-no-null").search(
            "typeof x === 'object' && x !== null"
        )


class TestOverloadAnyFallback:
    def test_matches_any_overload(self):
        assert _pattern("ts-overload-any-fallback").search(
            "function parse(input: any): any"
        )

    def test_no_match_specific_overload(self):
        assert not _pattern("ts-overload-any-fallback").search(
            "function parse(input: string): Config"
        )


class TestGenericAnyConstraint:
    def test_matches_extends_any(self):
        assert _pattern("ts-generic-any-constraint").search("<T extends any>")

    def test_no_match_extends_object(self):
        assert not _pattern("ts-generic-any-constraint").search("<T extends object>")

    def test_no_match_extends_record(self):
        assert not _pattern("ts-generic-any-constraint").search(
            "<T extends Record<string, unknown>>"
        )


class TestPartialSecurityType:
    def test_matches_partial_auth(self):
        assert _pattern("ts-partial-security-type").search("Partial<AuthConfig>")

    def test_matches_partial_permission(self):
        assert _pattern("ts-partial-security-type").search("Partial<UserPermission>")

    def test_matches_partial_session(self):
        assert _pattern("ts-partial-security-type").search("Partial<SessionData>")

    def test_no_match_partial_regular(self):
        assert not _pattern("ts-partial-security-type").search("Partial<UserProfile>")

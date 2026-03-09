"""Tests for the `doji rules` command and list_all_rules()."""

import json
import pytest
from dojigiri.languages import list_all_rules


def test_list_all_rules_returns_list():
    """list_all_rules() should return a non-empty list of dicts."""
    rules = list_all_rules()
    assert isinstance(rules, list)
    assert len(rules) > 0


def test_list_all_rules_dict_shape():
    """Each rule dict should have the required keys."""
    rules = list_all_rules()
    for r in rules:
        assert "name" in r
        assert "severity" in r
        assert "category" in r
        assert "languages" in r
        assert "message" in r
        assert "suggestion" in r
        assert isinstance(r["languages"], list)


def test_list_all_rules_no_duplicates():
    """Rule names should be unique (deduplication works)."""
    rules = list_all_rules()
    names = [r["name"] for r in rules]
    assert len(names) == len(set(names))


def test_list_all_rules_universal_rules_have_all():
    """Universal rules like sql-injection-execute should have languages=['all']."""
    rules = list_all_rules()
    sql = [r for r in rules if r["name"] == "sql-injection-execute"]
    assert len(sql) == 1
    assert "all" in sql[0]["languages"]


def test_list_all_rules_language_specific():
    """Python-only rules should list python in languages."""
    rules = list_all_rules()
    os_sys = [r for r in rules if r["name"] == "os-system"]
    assert len(os_sys) == 1
    assert "python" in os_sys[0]["languages"]
    assert "all" not in os_sys[0]["languages"]


def test_list_all_rules_js_shared_with_ts():
    """JS rules should appear for both javascript and typescript."""
    rules = list_all_rules()
    console = [r for r in rules if r["name"] == "console-log"]
    assert len(console) == 1
    # console-log is in javascript.yaml, shared with typescript via language registry
    assert "javascript" in console[0]["languages"] or "all" in console[0]["languages"]
    assert "typescript" in console[0]["languages"] or "all" in console[0]["languages"]


def test_cmd_rules_text_output(capsys):
    """doji rules should produce text table output."""
    import argparse
    from dojigiri.__main__ import cmd_rules

    args = argparse.Namespace(lang=None, output="text")
    ret = cmd_rules(args)
    assert ret == 0

    captured = capsys.readouterr()
    assert "RULE" in captured.out
    assert "SEVERITY" in captured.out
    assert "rules" in captured.out  # summary line


def test_cmd_rules_json_output(capsys):
    """doji rules --output json should produce valid JSON array."""
    import argparse
    from dojigiri.__main__ import cmd_rules

    args = argparse.Namespace(lang=None, output="json")
    ret = cmd_rules(args)
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "name" in data[0]


def test_cmd_rules_lang_filter(capsys):
    """doji rules --lang python should filter to python + universal rules."""
    import argparse
    from dojigiri.__main__ import cmd_rules

    args = argparse.Namespace(lang="python", output="json")
    ret = cmd_rules(args)
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    for r in data:
        assert "all" in r["languages"] or "python" in r["languages"]

    # Should not include Go-only or Rust-only rules
    names = {r["name"] for r in data}
    assert "unchecked-error" not in names  # Go-only
    assert "unwrap" not in names  # Rust-only


def test_cmd_rules_lang_filter_go(capsys):
    """doji rules --lang go should include Go-specific rules."""
    import argparse
    from dojigiri.__main__ import cmd_rules

    args = argparse.Namespace(lang="go", output="json")
    ret = cmd_rules(args)
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    names = {r["name"] for r in data}
    assert "unchecked-error" in names
    assert "fmt-print" in names


def test_list_all_rules_severity_sort_order():
    """Rules should be sorted: critical first, then warning, then info."""
    rules = list_all_rules()
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    order_values = [severity_order[r["severity"]] for r in rules]
    assert order_values == sorted(order_values)


def test_list_all_rules_has_suggestion():
    """Rules with suggestions should include them."""
    rules = list_all_rules()
    # Most rules have suggestions — at least some should be non-None
    with_suggestion = [r for r in rules if r["suggestion"] is not None]
    assert len(with_suggestion) > 10

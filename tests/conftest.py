"""Shared test fixtures for Wiz test suite."""

import pytest
import tempfile
from pathlib import Path
from dojigiri.config import Finding, FileAnalysis, ScanReport, Severity, Category, Source


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_python_code():
    """Sample Python code with various issues for testing."""
    return '''
import unused_module
import os

def test_function():
    password = "hardcoded_secret_key_12345"
    x = eval("1 + 1")
    
    try:
        risky_operation()
    except:
        pass
    
    list = [1, 2, 3]  # shadows builtin
    
    if type(x) == int:  # should use isinstance
        return True
    
    return False
    print("unreachable")  # dead code

def complex_function(a, b, c, d, e, f, g, h, i):  # too many args
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        return True
    return False
'''


@pytest.fixture
def sample_javascript_code():
    """Sample JavaScript code with issues."""
    return '''
var oldStyle = true;
console.log("debug");

function test() {
    if (x == 5) {  // loose equality
        eval("dangerous");
        document.write("bad");
        element.innerHTML = userInput;
    }
}
'''


@pytest.fixture
def sample_go_code():
    """Sample Go code with issues."""
    return '''
package main

import "fmt"

func main() {
    result, _ := riskyOperation()  // unchecked error
    fmt.Println(result)
}
'''


@pytest.fixture
def sample_rust_code():
    """Sample Rust code with issues."""
    return '''
fn main() {
    let value = Some(5);
    let x = value.unwrap();
    
    let result = risky_operation().expect("failed");
    
    unsafe {
        dangerous_operation();
    }
}
'''


@pytest.fixture
def sample_finding():
    """Create a sample Finding instance."""
    return Finding(
        file="test.py",
        line=10,
        severity=Severity.WARNING,
        category=Category.BUG,
        source=Source.STATIC,
        rule="test-rule",
        message="Test message",
        suggestion="Test suggestion",
        snippet="test code",
    )


@pytest.fixture
def sample_file_analysis(sample_finding):
    """Create a sample FileAnalysis instance."""
    return FileAnalysis(
        path="test.py",
        language="python",
        lines=100,
        findings=[sample_finding],
        file_hash="abc123",
    )


@pytest.fixture
def sample_scan_report(sample_file_analysis):
    """Create a sample ScanReport instance."""
    return ScanReport(
        root="/test/path",
        mode="quick",
        files_scanned=5,
        files_skipped=2,
        total_findings=10,
        critical=2,
        warnings=5,
        info=3,
        file_analyses=[sample_file_analysis],
        llm_cost_usd=0.0,
        timestamp="2024-01-01T00:00:00",
    )

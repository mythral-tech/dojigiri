"""Tests for Java TOCTOU race condition detection rules.

Covers:
- java-toctou-file-check-then-act: Files.exists() as precondition (CWE-367)
- java-async-file-operation: File mutations in @Async methods (CWE-367)
"""

import pytest
from dojigiri.detector import run_regex_checks


# ─── java-toctou-file-check-then-act ────────────────────────────────────


class TestToctouFileCheckThenAct:
    """Detect Files.exists() used as a precondition — the check itself is the
    antipattern because it's never atomic with the subsequent file operation."""

    def test_files_exists_in_if_condition(self):
        code = '''\
        if (Files.exists(target)) {
            Files.delete(target);
        }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 1
        assert "Files.exists" in toctou[0].snippet

    def test_files_exists_negated(self):
        code = '''\
        if (!Files.exists(target) || !isOwner(target, username)) {
            throw new SecurityException("Not your file");
        }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 1

    def test_files_exists_with_and_condition(self):
        code = '''\
        if (Files.exists(target) && !isOwner(target, username)) {
            throw new SecurityException("Not your file");
        }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 1

    def test_files_exists_standalone_check(self):
        """Files.exists used as a standalone expression (not in if)."""
        code = '''\
        boolean exists = Files.exists(path);
'''
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 1

    def test_no_false_positive_on_files_copy_alone(self):
        """Files.copy without preceding Files.exists should NOT trigger TOCTOU."""
        code = '''\
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
'''
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 0

    def test_severity_is_warning(self):
        code = 'if (Files.exists(target)) {'
        findings = run_regex_checks(code, "Service.java", "java")
        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 1
        assert toctou[0].severity.name == "WARNING"


# ─── java-async-file-operation ──────────────────────────────────────────


class TestAsyncFileOperation:
    """Detect filesystem mutations inside @Async methods — inherently
    race-prone because multiple threads may operate on the same file."""

    def test_async_files_copy(self):
        code = '''\
    @Async
    public void processUpload(String username, MultipartFile file)
            throws IOException {
        Path target = Paths.get("/uploads").resolve(file.getOriginalFilename());
        Files.copy(file.getInputStream(), target,
                StandardCopyOption.REPLACE_EXISTING);
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 1
        assert "Files.copy" in async_findings[0].snippet

    def test_async_files_delete(self):
        code = '''\
    @Async
    public void deleteFile(String filename) throws IOException {
        Path target = Paths.get("/uploads").resolve(filename);
        Files.delete(target);
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 1
        assert "Files.delete" in async_findings[0].snippet

    def test_async_files_move(self):
        code = '''\
    @Async
    public void moveFile(Path src, Path dst) throws IOException {
        Files.move(src, dst);
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 1

    def test_async_files_write(self):
        code = '''\
    @Async
    public void writeData(Path path, byte[] data) throws IOException {
        Files.write(path, data);
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 1

    def test_no_async_annotation_suppresses_rule(self):
        """File mutations without @Async should NOT trigger this rule."""
        code = '''\
    public void processFile(Path target) throws IOException {
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        Files.delete(target);
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 0

    def test_severity_is_info(self):
        code = '''\
    @Async
    public void doWork() throws IOException {
        Files.delete(Paths.get("/tmp/test"));
    }
'''
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 1
        assert async_findings[0].severity.name == "INFO"

    def test_async_too_far_away_suppresses(self):
        """@Async more than 30 lines above should not trigger the rule."""
        lines = ["    @Async\n", "    public void method() {\n"]
        # 35 filler lines
        lines += ["        int x = 0;\n"] * 35
        lines += ["        Files.delete(target);\n", "    }\n"]
        code = "".join(lines)
        findings = run_regex_checks(code, "Service.java", "java")
        async_findings = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_findings) == 0


# ─── Benchmark integration ──────────────────────────────────────────────


class TestBenchmarkCase:
    """Verify both rules fire on the actual benchmark file."""

    def test_benchmark_async_file_processor(self):
        import os
        benchmark = os.path.join(
            os.path.dirname(__file__), "..",
            "benchmarks", "vs_semgrep", "java",
            "race_condition_async", "AsyncFileProcessor.java",
        )
        with open(benchmark) as f:
            code = f.read()

        findings = run_regex_checks(code, benchmark, "java")

        toctou = [f for f in findings if f.rule == "java-toctou-file-check-then-act"]
        assert len(toctou) == 2, f"Expected 2 TOCTOU findings, got {len(toctou)}"
        assert toctou[0].line == 21
        assert toctou[1].line == 36

        async_ops = [f for f in findings if f.rule == "java-async-file-operation"]
        assert len(async_ops) == 2, f"Expected 2 async findings, got {len(async_ops)}"
        assert async_ops[0].line == 27
        assert async_ops[1].line == 41

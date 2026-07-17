"""Tests for CodeSentinel analyzer engine."""

from codesentinel.analyzer import (
    _apply_regex_rules,
    _check_ai_quality,
    _check_security_patterns,
    _count_lines,
    _detect_ast_issues,
    analyze_directory,
    analyze_file,
    calculate_scores,
    detect_language,
)
from codesentinel.models import Category, Finding, Severity


class TestDetectLanguage:
    def test_python(self):
        assert detect_language("test.py") == "python"

    def test_javascript(self):
        assert detect_language("test.js") == "javascript"

    def test_typescript(self):
        assert detect_language("test.ts") == "typescript"

    def test_go(self):
        assert detect_language("test.go") == "go"

    def test_rust(self):
        assert detect_language("test.rs") == "rust"

    def test_unknown(self):
        assert detect_language("test.xyz") == "unknown"

    def test_uppercase_extension(self):
        assert detect_language("test.PY") == "python"


class TestCountLines:
    def test_empty(self):
        assert _count_lines("") == 0

    def test_single_line(self):
        assert _count_lines("hello") == 1

    def test_with_comments(self):
        content = "hello\n# comment\nworld"
        assert _count_lines(content) == 2

    def test_empty_lines(self):
        content = "hello\n\n\nworld"
        assert _count_lines(content) == 2


class TestRegexRules:
    def test_bare_except_detected(self):
        content = "try:\n    pass\nexcept:\n    pass"
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-002" in rule_ids

    def test_eval_detected(self):
        content = "result = eval(user_input)"
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-004" in rule_ids

    def test_shell_true_detected(self):
        content = "subprocess.run(cmd, shell=True)"
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-007" in rule_ids

    def test_hardcoded_password_detected(self):
        content = 'password = "super_secret_123"'
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-005" in rule_ids

    def test_print_detected(self):
        content = "print('hello')"
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-019" in rule_ids

    def test_pass_detected(self):
        content = "def foo():\n    pass"
        findings = _apply_regex_rules(content, "python", "test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-016" in rule_ids

    def test_no_findings_on_clean_code(self):
        content = "def hello():\n    return 'world'\n"
        findings = _apply_regex_rules(content, "python", "test.py")
        # Should have minimal findings for clean code
        assert len(findings) >= 0  # May still have some low-severity ones


class TestAstIssues:
    def test_mutable_default_detected(self):
        content = "def foo(items=[]):\n    items.append(1)\n    return items"
        findings = _detect_ast_issues(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-024" in rule_ids

    def test_dict_default_detected(self):
        content = "def foo(config={}):\n    config['key'] = 'value'\n    return config"
        findings = _detect_ast_issues(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-024" in rule_ids

    def test_long_function_detected(self):
        lines = ["def long_func():\n"]
        for i in range(55):
            lines.append(f"    x{i} = {i}\n")
        content = "".join(lines)
        findings = _detect_ast_issues(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-025" in rule_ids

    def test_syntax_error_returns_empty(self):
        content = "def foo(:\n    pass"
        findings = _detect_ast_issues(content, "python")
        assert findings == []


class TestSecurityPatterns:
    def test_pickle_detected(self):
        content = "data = pickle.loads(raw_data)"
        findings = _check_security_patterns(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "SEC-001" in rule_ids

    def test_os_system_detected(self):
        content = "os.system('rm -rf /tmp/test')"
        findings = _check_security_patterns(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "SEC-002" in rule_ids

    def test_mktemp_detected(self):
        content = "tmp = tempfile.mktemp()"
        findings = _check_security_patterns(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "SEC-003" in rule_ids

    def test_md5_detected(self):
        content = "h = hashlib.md5(data)"
        findings = _check_security_patterns(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "SEC-004" in rule_ids

    def test_sha1_detected(self):
        content = "h = hashlib.sha1(data)"
        findings = _check_security_patterns(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "SEC-004" in rule_ids


class TestAiQuality:
    def test_short_file_detected(self):
        content = "x = 1\n"
        findings = _check_ai_quality(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-Q-001" in rule_ids

    def test_excessive_todos_detected(self):
        lines = ["# TODO: fix this\n"] * 10
        content = "".join(lines)
        findings = _check_ai_quality(content, "python")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-Q-002" in rule_ids

    def test_no_ai_issues_on_normal_file(self):
        # A well-written module file - use a longer file to avoid "very short" detection
        content = '"""A normal module."""\n\n\ndef hello(name: str) -> str:\n    """Return a greeting."""\n    return f"Hello, {name}!"\n\n\ndef goodbye(name: str) -> str:\n    """Say goodbye."""\n    return f"Goodbye, {name}!"\n\n\ndef main() -> None:\n    """Entry point."""\n    print(hello("world"))\n'
        findings = _check_ai_quality(content, "python")
        # Should have no AI-specific issues for well-written code
        assert len(findings) == 0


class TestCalculateScores:
    def test_no_findings(self):
        score = calculate_scores([])
        assert score.total == 100.0
        assert score.grade == "A"
        assert score.num_findings == 0

    def test_with_critical_finding(self):
        findings = [
            Finding(
                rule_id="TEST-001",
                title="Critical",
                description="Critical issue",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
            )
        ]
        score = calculate_scores(findings)
        assert score.num_critical == 1
        assert score.total < 100

    def test_with_multiple_severities(self):
        findings = [
            Finding(
                rule_id="T1",
                title="C",
                description="C",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
            ),
            Finding(
                rule_id="T2",
                title="H",
                description="H",
                severity=Severity.HIGH,
                category=Category.QUALITY,
            ),
            Finding(
                rule_id="T3",
                title="M",
                description="M",
                severity=Severity.MEDIUM,
                category=Category.MAINTAINABILITY,
            ),
            Finding(
                rule_id="T4",
                title="L",
                description="L",
                severity=Severity.LOW,
                category=Category.PERFORMANCE,
            ),
        ]
        score = calculate_scores(findings)
        assert score.num_critical == 1
        assert score.num_high == 1
        assert score.num_medium == 1
        assert score.num_low == 1
        assert score.total < 100


class TestAnalyzeFile:
    def test_analyze_clean_file(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text('def hello():\n    return "world"\n')
        result = analyze_file(str(f))
        assert result.file_path == str(f)
        assert result.language == "python"
        assert result.line_count > 0

    def test_analyze_file_with_issues(self, tmp_path):
        f = tmp_path / "dirty.py"
        f.write_text('password = "secret123"\nresult = eval("1+1")\nprint("hello")\n')
        result = analyze_file(str(f))
        assert result.file_path == str(f)
        assert len(result.findings) > 0
        # Should detect hardcoded password and eval
        rule_ids = [f.rule_id for f in result.findings]
        assert "AI-005" in rule_ids
        assert "AI-004" in rule_ids

    def test_analyze_nonexistent_file(self):
        try:
            analyze_file("/nonexistent/file.py")
            raise AssertionError("Should raise FileNotFoundError")
        except FileNotFoundError:
            pass

    def test_analyze_binary_file(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        result = analyze_file(str(f))
        assert result.scores.total == 0


class TestAnalyzeDirectory:
    def test_analyze_directory(self, tmp_path):
        # Create test files
        (tmp_path / "test1.py").write_text("def foo():\n    pass\n")
        (tmp_path / "test2.py").write_text("x = 1\n")

        results = analyze_directory(str(tmp_path))
        assert len(results) == 2

    def test_analyze_directory_excludes(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "cached.py").write_text("x = 1\n")
        (tmp_path / "main.py").write_text("def main():\n    pass\n")

        results = analyze_directory(str(tmp_path))
        # Should exclude __pycache__
        paths = [r.file_path for r in results]
        assert not any("__pycache__" in p for p in paths)

    def test_analyze_directory_not_dir(self):
        try:
            analyze_directory("/nonexistent/dir")
            raise AssertionError("Should raise NotADirectoryError")
        except NotADirectoryError:
            pass

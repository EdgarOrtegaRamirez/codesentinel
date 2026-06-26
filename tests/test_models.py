"""Tests for CodeSentinel models."""

from codesentinel.models import (
    AnalysisResult,
    Category,
    Finding,
    Score,
    Severity,
)


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestCategory:
    def test_category_values(self):
        assert Category.SECURITY.value == "security"
        assert Category.QUALITY.value == "quality"
        assert Category.AI_PATTERNS.value == "ai_patterns"
        assert Category.MAINTAINABILITY.value == "maintainability"
        assert Category.PERFORMANCE.value == "performance"
        assert Category.BEST_PRACTICES.value == "best_practices"


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            rule_id="TEST-001",
            title="Test finding",
            description="A test finding",
            severity=Severity.MEDIUM,
            category=Category.QUALITY,
            line=42,
            suggestion="Fix this",
        )
        assert f.rule_id == "TEST-001"
        assert f.title == "Test finding"
        assert f.line == 42
        assert f.is_blocking is False

    def test_finding_critical_is_blocking(self):
        f = Finding(
            rule_id="TEST-002",
            title="Critical issue",
            description="Should block",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
        )
        assert f.is_blocking is True

    def test_finding_high_is_blocking(self):
        f = Finding(
            rule_id="TEST-003",
            title="High issue",
            description="Should block",
            severity=Severity.HIGH,
            category=Category.SECURITY,
        )
        assert f.is_blocking is True

    def test_finding_to_dict(self):
        f = Finding(
            rule_id="TEST-004",
            title="Dict test",
            description="Test serialization",
            severity=Severity.LOW,
            category=Category.INFO,
            line=10,
            suggestion="Do something",
            confidence=0.8,
        )
        d = f.to_dict()
        assert d["rule_id"] == "TEST-004"
        assert d["severity"] == "low"
        assert d["line"] == 10
        assert d["confidence"] == 0.8
        assert d["ai_pattern"] is False


class TestScore:
    def test_score_default(self):
        s = Score()
        assert s.total == 100.0
        assert s.grade == "A"
        assert s.is_passing is True

    def test_score_grade_a(self):
        s = Score(total=95)
        assert s.grade == "A"

    def test_score_grade_b(self):
        s = Score(total=85)
        assert s.grade == "B"

    def test_score_grade_c(self):
        s = Score(total=75)
        assert s.grade == "C"

    def test_score_grade_d(self):
        s = Score(total=65)
        assert s.grade == "D"

    def test_score_grade_f(self):
        s = Score(total=30)
        assert s.grade == "F"

    def test_score_is_passing(self):
        s = Score(total=60)
        assert s.is_passing is True

    def test_score_not_passing(self):
        s = Score(total=59)
        assert s.is_passing is False

    def test_score_to_dict(self):
        s = Score(total=85)
        d = s.to_dict()
        assert d["total"] == 85.0
        assert d["grade"] == "B"
        assert "is_passing" in d

    def test_score_counts(self):
        s = Score(
            num_findings=10,
            num_critical=1,
            num_high=2,
            num_medium=3,
            num_low=4,
        )
        assert s.num_findings == 10
        assert s.num_critical == 1
        assert s.num_high == 2


class TestAnalysisResult:
    def test_analysis_result_creation(self):
        r = AnalysisResult(
            file_path="test.py",
            scores=Score(total=90),
            language="python",
            line_count=100,
        )
        assert r.file_path == "test.py"
        assert r.language == "python"
        assert r.line_count == 100

    def test_analysis_result_to_dict(self):
        r = AnalysisResult(
            file_path="test.py",
            scores=Score(total=80),
            findings=[
                Finding(
                    rule_id="T-001",
                    title="Test",
                    description="Desc",
                    severity=Severity.LOW,
                    category=Category.INFO,
                )
            ],
        )
        d = r.to_dict()
        assert d["file_path"] == "test.py"
        assert d["scores"]["total"] == 80.0
        assert len(d["findings"]) == 1

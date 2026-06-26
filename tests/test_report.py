"""Tests for CodeSentinel CLI and reports."""

import json
import tempfile
from pathlib import Path

from codesentinel.report import (
    format_text_report,
    format_json_report,
    format_markdown_report,
    save_report,
)
from codesentinel.models import AnalysisResult, Score, Finding, Severity, Category


class TestReportFormats:
    def test_text_report(self):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=85),
            findings=[
                Finding(
                    rule_id="T-001",
                    title="Test issue",
                    description="A test issue",
                    severity=Severity.LOW,
                    category=Category.INFO,
                    line=10,
                    suggestion="Fix this",
                )
            ],
            language="python",
            line_count=20,
        )
        report = format_text_report([result])
        assert "CodeSentinel" in report
        assert "test.py" in report
        assert "B" in report
        assert "85.0" in report
        assert "Test issue" in report

    def test_json_report(self):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=90),
            language="python",
            line_count=50,
        )
        report = format_json_report([result])
        data = json.loads(report)
        assert data["files"][0]["file_path"] == "test.py"
        assert data["files"][0]["scores"]["total"] == 90.0
        assert data["summary"]["files_analyzed"] == 1

    def test_markdown_report(self):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=75),
            language="python",
            line_count=30,
        )
        report = format_markdown_report(results=[result])
        assert "# CodeSentinel" in report
        assert "test.py" in report
        assert "Summary" in report

    def test_save_report_text(self, tmp_path):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=80),
            language="python",
        )
        output = tmp_path / "reports" / "report.txt"
        saved = save_report([result], str(output), "text")
        assert Path(saved).exists()
        content = Path(saved).read_text()
        assert "CodeSentinel" in content

    def test_save_report_json(self, tmp_path):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=80),
            language="python",
        )
        output = tmp_path / "reports" / "report.json"
        saved = save_report([result], str(output), "json")
        assert Path(saved).exists()
        content = Path(saved).read_text()
        data = json.loads(content)
        assert data["summary"]["files_analyzed"] == 1

    def test_save_report_markdown(self, tmp_path):
        result = AnalysisResult(
            file_path="test.py",
            scores=Score(total=80),
            language="python",
        )
        output = tmp_path / "reports" / "report.md"
        saved = save_report([result], str(output), "markdown")
        assert Path(saved).exists()
        content = Path(saved).read_text()
        assert "# CodeSentinel" in content

    def test_multiple_files_report(self):
        results = [
            AnalysisResult(file_path="a.py", scores=Score(total=90), language="python", line_count=10),
            AnalysisResult(file_path="b.py", scores=Score(total=70), language="python", line_count=20),
        ]
        report = format_text_report(results)
        assert "a.py" in report
        assert "b.py" in report

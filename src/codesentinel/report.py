"""Report generators for CodeSentinel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from codesentinel.analyzer import AnalysisResult


def format_text_report(results: List[AnalysisResult]) -> str:
    """Format analysis results as a human-readable text report."""
    lines = []
    lines.append("=" * 72)
    lines.append("  CodeSentinel - AI Code Quality Report")
    lines.append("=" * 72)
    lines.append("")

    for result in results:
        lines.append(f"📄 {result.file_path}")
        lines.append(f"   Language: {result.language} | Lines: {result.line_count}")
        lines.append(f"   Grade: {result.scores.grade} | Score: {result.scores.total:.1f}/100")

        if result.scores.is_passing:
            lines.append(f"   Status: ✅ PASSING")
        else:
            lines.append(f"   Status: ❌ FAILING")
        lines.append("")

        # Category breakdown
        lines.append("   ┌─────────────────────┬────────┬──────────────────┐")
        lines.append("   │ Category            │ Score  │ Status           │")
        lines.append("   ├─────────────────────┼────────┼──────────────────┤")

        categories = [
            ("Security", result.scores.security),
            ("Quality", result.scores.quality),
            ("Maintainability", result.scores.maintainability),
            ("Performance", result.scores.performance),
            ("AI Quality", result.scores.ai_quality),
        ]

        for cat_name, cat_score in categories:
            status = "✅" if cat_score >= 70 else ("⚠️" if cat_score >= 50 else "❌")
            lines.append(f"   │ {cat_name:<18} │ {cat_score:>6.1f} │ {status} {' ' * 10} │")

        lines.append("   └─────────────────────┴────────┴──────────────────┘")
        lines.append("")

        # Findings by severity
        if result.findings:
            severity_groups = {}
            for f in result.findings:
                severity_groups.setdefault(f.severity.value, []).append(f)

            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev not in severity_groups:
                    continue
                findings = severity_groups[sev]
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}[sev]
                lines.append(f"   {icon} {sev.upper()} ({len(findings)}):")
                for f in findings:
                    loc = f"line {f.line}" if f.line else "global"
                    lines.append(f"     • [{f.rule_id}] {f.title} ({loc})")
                    if f.suggestion:
                        lines.append(f"       → {f.suggestion}")
                lines.append("")
        else:
            lines.append("   ✅ No issues found!")
            lines.append("")

        lines.append("-" * 72)
        lines.append("")

    # Summary
    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.scores.num_critical for r in results)
    total_high = sum(r.scores.num_high for r in results)
    avg_score = sum(r.scores.total for r in results) / max(len(results), 1)

    lines.append("📊 SUMMARY")
    lines.append(f"   Files analyzed: {len(results)}")
    lines.append(f"   Total findings: {total_findings}")
    lines.append(f"   Critical: {total_critical} | High: {total_high} | Medium: {sum(r.scores.num_medium for r in results)} | Low: {sum(r.scores.num_low for r in results)}")
    lines.append(f"   Average score: {avg_score:.1f}/100 (Grade: {chr(65 + min(int(avg_score // 10) - 6, 4))})")
    lines.append("=" * 72)

    return "\n".join(lines)


def format_json_report(results: List[AnalysisResult]) -> str:
    """Format analysis results as JSON."""
    data = {
        "report": "CodeSentinel Analysis Report",
        "files": [r.to_dict() for r in results],
        "summary": {
            "files_analyzed": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "total_critical": sum(r.scores.num_critical for r in results),
            "total_high": sum(r.scores.num_high for r in results),
            "average_score": round(sum(r.scores.total for r in results) / max(len(results), 1), 1),
        },
    }
    return json.dumps(data, indent=2)


def format_markdown_report(results: List[AnalysisResult]) -> str:
    """Format analysis results as Markdown."""
    lines = []
    lines.append("# CodeSentinel - AI Code Quality Report\n")

    for result in results:
        lines.append(f"## 📄 `{result.file_path}`\n")
        lines.append(f"- **Language:** {result.language}")
        lines.append(f"- **Lines:** {result.line_count}")
        lines.append(f"- **Grade:** {result.scores.grade} ({result.scores.total:.1f}/100)")
        lines.append(f"- **Status:** {'✅ PASSING' if result.scores.is_passing else '❌ FAILING'}\n")

        # Score table
        lines.append("### Score Breakdown")
        lines.append("")
        lines.append("| Category | Score | Status |")
        lines.append("|----------|-------|--------|")

        categories = [
            ("Security", result.scores.security),
            ("Quality", result.scores.quality),
            ("Maintainability", result.scores.maintainability),
            ("Performance", result.scores.performance),
            ("AI Quality", result.scores.ai_quality),
        ]

        for cat_name, cat_score in categories:
            status = "✅" if cat_score >= 70 else ("⚠️" if cat_score >= 50 else "❌")
            lines.append(f"| {cat_name} | {cat_score:.1f} | {status} |")

        lines.append("")

        if result.findings:
            lines.append("### Findings\n")
            for f in result.findings:
                loc = f" (line {f.line})" if f.line else ""
                lines.append(f"- **[{f.severity.value.upper()}]** {f.title}{loc}")
                lines.append(f"  - {f.description}")
                if f.suggestion:
                    lines.append(f"  - **Fix:** {f.suggestion}")
            lines.append("")
        else:
            lines.append("✅ No issues found!\n")

        lines.append("---\n")

    # Summary
    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.scores.num_critical for r in results)
    total_high = sum(r.scores.num_high for r in results)
    avg_score = sum(r.scores.total for r in results) / max(len(results), 1)

    lines.append("## 📊 Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Files analyzed | {len(results)} |")
    lines.append(f"| Total findings | {total_findings} |")
    lines.append(f"| Critical | {total_critical} |")
    lines.append(f"| High | {total_high} |")
    lines.append(f"| Average score | {avg_score:.1f}/100 |")
    lines.append("")

    return "\n".join(lines)


def save_report(results: List[AnalysisResult], output_path: str, format: str = "text") -> str:
    """Save report to file and return the path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        content = format_json_report(results)
    elif format == "markdown":
        content = format_markdown_report(results)
    else:
        content = format_text_report(results)

    path.write_text(content, encoding="utf-8")
    return str(path)

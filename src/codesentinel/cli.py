"""CLI interface for CodeSentinel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codesentinel.__init__ import __version__
from codesentinel.analyzer import analyze_directory, analyze_file
from codesentinel.report import (
    format_json_report,
    format_markdown_report,
    format_text_report,
    save_report,
)


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a scan on a file or directory."""
    path = Path(args.path)

    if not path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 1

    if path.is_file():
        results = [analyze_file(str(path))]
    else:
        results = analyze_directory(
            str(path),
            extensions=args.extensions,
            exclude=args.exclude,
        )

    # Generate report
    if args.format == "json":
        output = format_json_report(results)
    elif args.format == "markdown":
        output = format_markdown_report(results)
    else:
        output = format_text_report(results)

    if args.output:
        save_report(results, args.output, args.format)
        print(f"Report saved to: {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code based on severity
    has_blocking = any(f.is_blocking for r in results for f in r.findings)
    if args.fail_on_severity:
        severities = {"critical", "high", "medium", "low"}
        threshold_idx = list(severities).index(args.fail_on_severity)
        has_blocking = any(
            list(severities).index(f.severity.value) <= threshold_idx
            for r in results
            for f in r.findings
        )

    if has_blocking and not args.quiet:
        return 2
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """List available rules."""
    from codesentinel.rules import get_rules

    rules = get_rules()

    if args.category:
        from codesentinel.models import Category

        try:
            cat = Category(args.category)
            rules = [r for r in rules if r.category == cat]
        except ValueError:
            print(f"Invalid category: {args.category}", file=sys.stderr)
            print(f"Valid categories: {', '.join(c.value for c in Category)}", file=sys.stderr)
            return 1

    if args.severity:
        from codesentinel.models import Severity

        try:
            sev = Severity(args.severity)
            rules = [r for r in rules if r.severity == sev]
        except ValueError:
            print(f"Invalid severity: {args.severity}", file=sys.stderr)
            print(f"Valid severities: {', '.join(s.value for s in Severity)}", file=sys.stderr)
            return 1

    if args.json:
        data = {
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "description": r.description,
                    "severity": r.severity.value,
                    "category": r.category.value,
                    "suggestion": r.suggestion,
                    "confidence": r.confidence,
                    "ai_pattern": r.ai_pattern,
                }
                for r in rules
            ]
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Available rules ({len(rules)}):\n")
        for r in rules:
            ai_tag = " [AI]" if r.ai_pattern else ""
            print(f"  {r.rule_id} | [{r.severity.value.upper()}] {r.category.value}{ai_tag}")
            print(f"           {r.title}")
            print(f"           {r.description}")
            if r.suggestion:
                print(f"           Fix: {r.suggestion}")
            print()

    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    """Generate a sample config file."""
    config = {
        "version": "1.0",
        "scan": {
            "paths": ["src/"],
            "extensions": [".py", ".js", ".ts", ".tsx"],
            "exclude": [".git", "__pycache__", "node_modules", ".venv"],
        },
        "thresholds": {
            "min_score": 60,
            "fail_on": "high",  # critical, high, medium, low
            "max_findings": {
                "critical": 0,
                "high": 5,
                "medium": 20,
                "low": 50,
            },
        },
        "categories": {
            "security": {"enabled": True, "weight": 0.30},
            "quality": {"enabled": True, "weight": 0.15},
            "maintainability": {"enabled": True, "weight": 0.15},
            "performance": {"enabled": True, "weight": 0.10},
            "ai_patterns": {"enabled": True, "weight": 0.10},
            "best_practices": {"enabled": True, "weight": 0.20},
        },
        "report": {
            "format": "text",  # text, json, markdown
            "output": "reports/codesentinel-report.txt",
        },
        "rules": {
            "enabled": [],  # empty = all enabled
            "disabled": [],  # rule IDs to disable, e.g. ["AI-012"]
        },
    }

    output_path = args.output or "codesentinel.yaml"
    import yaml

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    print(f"Sample config written to: {output_path}")
    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="AI-generated code quality and security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  codesentinel scan src/                          Scan a directory
  codesentinel scan main.py --format json         Scan a file as JSON
  codesentinel rules --category security          List security rules
  codesentinel rules --severity critical           List critical rules
  codesentinel sample-config                      Generate a sample config
        """,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for quality issues")
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument("--output", "-o", help="Output file path")
    scan_parser.add_argument(
        "--extensions", nargs="+", default=None, help="File extensions to scan"
    )
    scan_parser.add_argument("--exclude", nargs="+", default=None, help="Directories to exclude")
    scan_parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low"],
        help="Fail CI if findings at this severity or above",
    )
    scan_parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress output on success"
    )

    # rules command
    rules_parser = subparsers.add_parser("rules", help="List available analysis rules")
    rules_parser.add_argument(
        "--category", help="Filter by category (security, quality, ai_patterns, etc.)"
    )
    rules_parser.add_argument(
        "--severity", help="Filter by severity (critical, high, medium, low, info)"
    )
    rules_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # sample-config command
    sample_parser = subparsers.add_parser(
        "sample-config", help="Generate a sample configuration file"
    )
    sample_parser.add_argument(
        "--output", "-o", default="codesentinel.yaml", help="Output file path"
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "rules":
        return cmd_rules(args)
    elif args.command == "sample-config":
        return cmd_sample(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Core analysis engine for CodeSentinel."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from codesentinel.models import (
    AnalysisResult,
    Category,
    Finding,
    Score,
    Severity,
)
from codesentinel.rules import CORE_RULES


def detect_language(file_path: str) -> str:
    """Detect the programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rb": "ruby",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".ps1": "powershell",
        ".sql": "sql",
        ".html": "html",
        ".css": "css",
        ".scss": "scss",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".xml": "xml",
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, "unknown")


def _count_lines(content: str) -> int:
    """Count non-empty, non-comment lines."""
    lines = content.splitlines()
    return len([line for line in lines if line.strip() and not line.strip().startswith("#")])


def _apply_regex_rules(content: str, language: str, file_path: str) -> list[Finding]:
    """Apply regex-based rules to the source content."""
    findings = []
    lines = content.splitlines()

    for rule in CORE_RULES:
        if (
            language != "python"
            and not rule.ai_pattern
            and rule.category not in (Category.SECURITY, Category.AI_PATTERNS)
        ):
            continue

        try:
            matches = list(re.finditer(rule.pattern, content, rule.flags))
        except re.error:
            continue

        for match in matches:
            line_num = content[: match.start()].count("\n") + 1
            line_content = lines[min(line_num - 1, len(lines) - 1)] if lines else ""

            finding = Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                category=rule.category,
                line=line_num,
                suggestion=rule.suggestion,
                confidence=rule.confidence,
                code_snippet=line_content.strip()[:200],
            )
            findings.append(finding)

    return findings


def _detect_ast_issues(content: str, language: str) -> list[Finding]:
    """Parse AST and detect issues that require structural analysis."""
    findings = []

    if language != "python":
        return findings

    try:
        tree = ast.parse(content)
    except SyntaxError:
        # If the file has syntax errors, we can't do AST analysis
        # but regex rules still apply
        return []

    # Check for mutable default arguments
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    finding = Finding(
                        rule_id="AI-024",
                        title="Mutable default argument",
                        description="Mutable default arguments (lists, dicts) are shared across calls.",
                        severity=Severity.HIGH,
                        category=Category.BEST_PRACTICES,
                        line=node.lineno,
                        suggestion="Use None as default and initialize inside the function.",
                        confidence=1.0,
                        code_snippet=f"def {node.name}(...)",
                        ai_pattern=True,
                    )
                    findings.append(finding)

    # Check for overly long functions
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.end_lineno and node.lineno:
            func_lines = node.end_lineno - node.lineno + 1
            if func_lines > 50:
                finding = Finding(
                    rule_id="AI-025",
                    title="Excessively long functions",
                    description=f"Function '{node.name}' is {func_lines} lines long.",
                    severity=Severity.MEDIUM,
                    category=Category.MAINTAINABILITY,
                    line=node.lineno,
                    suggestion="Break this function into smaller, focused helper functions.",
                    confidence=0.7,
                    code_snippet=f"def {node.name}(...)",
                    ai_pattern=True,
                )
                findings.append(finding)
                break  # Only report once for first long function

    return findings


def _check_security_patterns(content: str, language: str) -> list[Finding]:
    """Check for language-specific security patterns."""
    findings = []

    if language != "python":
        return findings

    # Check for use of pickle (security risk)
    pickle_pattern = re.compile(r"\bpickle\.(?:load|loads|Unpickler)\s*\(")
    for match in pickle_pattern.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        line_content = content.splitlines()[min(line_num - 1, len(content.splitlines()) - 1)]
        findings.append(
            Finding(
                rule_id="SEC-001",
                title="Unsafe pickle usage",
                description="Pickle can execute arbitrary code during deserialization.",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                line=line_num,
                suggestion="Use json or msgpack for safe serialization.",
                confidence=0.95,
                code_snippet=line_content.strip()[:200],
            )
        )

    # Check for use of os.system
    os_system_pattern = re.compile(r"\bos\.system\s*\(")
    for match in os_system_pattern.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        line_content = content.splitlines()[min(line_num - 1, len(content.splitlines()) - 1)]
        findings.append(
            Finding(
                rule_id="SEC-002",
                title="os.system() usage",
                description="os.system() is vulnerable to command injection.",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                line=line_num,
                suggestion="Use subprocess.run() with shell=False and a list of arguments.",
                confidence=1.0,
                code_snippet=line_content.strip()[:200],
            )
        )

    # Check for use of tempfile.mktemp (race condition)
    mktemp_pattern = re.compile(r"\btempfile\.mktemp\s*\(")
    for match in mktemp_pattern.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        line_content = content.splitlines()[min(line_num - 1, len(content.splitlines()) - 1)]
        findings.append(
            Finding(
                rule_id="SEC-003",
                title="tempfile.mktemp() usage",
                description="mktemp() has a race condition. Use mkstemp() instead.",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                line=line_num,
                suggestion="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile().",
                confidence=0.9,
                code_snippet=line_content.strip()[:200],
            )
        )

    # Check for use of weak hashing
    weak_hash_pattern = re.compile(r"\b(hashlib\.)?(md5|sha1)\s*\(")
    for match in weak_hash_pattern.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        line_content = content.splitlines()[min(line_num - 1, len(content.splitlines()) - 1)]
        findings.append(
            Finding(
                rule_id="SEC-004",
                title="Weak hash algorithm",
                description="MD5 and SHA1 are cryptographically broken.",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                line=line_num,
                suggestion="Use SHA-256 or stronger: hashlib.sha256().",
                confidence=0.95,
                code_snippet=line_content.strip()[:200],
            )
        )

    return findings


def _check_ai_quality(content: str, language: str) -> list[Finding]:
    """Check for AI-generated code quality issues."""
    findings = []

    if language != "python":
        return findings

    lines = content.splitlines()
    total_lines = len(lines)

    # Check for very short files (likely scaffolding)
    if total_lines < 10 and total_lines > 0:
        findings.append(
            Finding(
                rule_id="AI-Q-001",
                title="Very short file",
                description="Files under 10 lines may be scaffolding or incomplete.",
                severity=Severity.INFO,
                category=Category.AI_PATTERNS,
                suggestion="Consider if this file needs more substance or should be merged.",
                confidence=0.5,
            )
        )

    # Check for excessive use of 'TODO' comments
    todo_count = sum(1 for line in lines if re.search(r"#\s*TODO", line, re.IGNORECASE))
    if todo_count > 5:
        findings.append(
            Finding(
                rule_id="AI-Q-002",
                title="Excessive TODO comments",
                description=f"Found {todo_count} TODO comments. AI often generates code with many TODOs.",
                severity=Severity.LOW,
                category=Category.AI_PATTERNS,
                suggestion="Address TODOs or convert to proper issue tracking.",
                confidence=0.7,
            )
        )

    # Check for very long docstrings (AI often generates verbose docs)
    in_docstring = False
    docstring_lines = 0
    for line in lines:
        stripped = line.strip()
        if '"""' in stripped or "'''" in stripped:
            quote = '"""' if '"""' in stripped else "'''"
            count = stripped.count(quote)
            if count == 1:
                in_docstring = True
                docstring_lines = 1
            elif count >= 2:
                # Single-line docstring
                if len(stripped) > 200:
                    findings.append(
                        Finding(
                            rule_id="AI-Q-003",
                            title="Excessively verbose docstring",
                            description="AI often generates very long docstrings. Keep them concise.",
                            severity=Severity.INFO,
                            category=Category.AI_PATTERNS,
                            suggestion="Keep docstrings to 3-5 lines summarizing purpose, args, and return.",
                            confidence=0.6,
                        )
                    )
        elif in_docstring:
            docstring_lines += 1
            if docstring_lines > 20:
                findings.append(
                    Finding(
                        rule_id="AI-Q-004",
                        title="Very long docstring",
                        description=f"Docstring is {docstring_lines} lines. AI often over-generates docs.",
                        severity=Severity.INFO,
                        category=Category.AI_PATTERNS,
                        suggestion="Keep docstrings concise. Aim for 3-5 lines.",
                        confidence=0.6,
                    )
                )
                in_docstring = False

    return findings


def calculate_scores(findings: list[Finding]) -> Score:
    """Calculate quality scores from findings."""
    score = Score()
    score.num_findings = len(findings)

    # Count by severity
    for f in findings:
        if f.severity == Severity.CRITICAL:
            score.num_critical += 1
        elif f.severity == Severity.HIGH:
            score.num_high += 1
        elif f.severity == Severity.MEDIUM:
            score.num_medium += 1
        elif f.severity == Severity.LOW:
            score.num_low += 1

    # Calculate category scores (start at 100, deduct per finding)
    category_penalties = {
        Severity.CRITICAL: 15,
        Severity.HIGH: 8,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    categories = {
        Category.SECURITY: 0.0,
        Category.QUALITY: 0.0,
        Category.MAINTAINABILITY: 0.0,
        Category.PERFORMANCE: 0.0,
        Category.AI_PATTERNS: 0.0,
        Category.BEST_PRACTICES: 0.0,
    }
    category_counts = dict.fromkeys(categories, 0)

    for f in findings:
        penalty = category_penalties.get(f.severity, 0)
        categories[f.category] += penalty
        category_counts[f.category] += 1

    # Average score per category (if no findings in category, keep 100)
    for cat in categories:
        if category_counts[cat] > 0:
            categories[cat] = max(0, 100 - categories[cat])
        else:
            categories[cat] = 100.0

    score.security = categories[Category.SECURITY]
    score.quality = categories[Category.QUALITY]
    score.maintainability = categories[Category.MAINTAINABILITY]
    score.performance = categories[Category.PERFORMANCE]
    score.ai_quality = categories[Category.AI_PATTERNS]

    # Overall score: weighted average
    weights = {
        Category.SECURITY: 0.30,
        Category.BEST_PRACTICES: 0.20,
        Category.QUALITY: 0.15,
        Category.MAINTAINABILITY: 0.15,
        Category.PERFORMANCE: 0.10,
        Category.AI_PATTERNS: 0.10,
    }

    total = 0.0
    for cat, score_val in categories.items():
        total += score_val * weights.get(cat, 0)

    score.total = total

    return score


def analyze_file(
    file_path: str,
    rules: list | None = None,
) -> AnalysisResult:
    """Analyze a single file and return results."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        content = path.read_text(encoding="utf-8")
        # Quick check: look for null bytes which indicate binary content
        if "\x00" in content:
            return AnalysisResult(
                file_path=str(file_path),
                scores=Score(total=0),
                findings=[
                    Finding(
                        rule_id="ERR-001",
                        title="Binary or non-UTF-8 file",
                        description="Cannot read file as text.",
                        severity=Severity.INFO,
                        category=Category.INFO,
                    )
                ],
            )
    except UnicodeDecodeError:
        return AnalysisResult(
            file_path=str(file_path),
            scores=Score(total=0, grade="F"),
            findings=[
                Finding(
                    rule_id="ERR-001",
                    title="Binary or non-UTF-8 file",
                    description="Cannot read file as text.",
                    severity=Severity.INFO,
                    category=Category.INFO,
                )
            ],
        )

    language = detect_language(str(file_path))
    line_count = _count_lines(content)

    # Apply all checks
    regex_findings = _apply_regex_rules(content, language, str(file_path))
    ast_findings = _detect_ast_issues(content, language)
    security_findings = _check_security_patterns(content, language)
    ai_findings = _check_ai_quality(content, language)

    all_findings = regex_findings + ast_findings + security_findings + ai_findings

    # Deduplicate findings with same rule_id on same line
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.rule_id, f.line or 0)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    scores = calculate_scores(unique_findings)

    return AnalysisResult(
        file_path=str(file_path),
        scores=scores,
        findings=unique_findings,
        metadata={
            "language": language,
            "line_count": line_count,
            "rules_applied": len(rules or CORE_RULES),
        },
        language=language,
        line_count=line_count,
    )


def analyze_directory(
    dir_path: str,
    extensions: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[AnalysisResult]:
    """Analyze all files in a directory."""
    from pathlib import Path as _Path

    if extensions is None:
        extensions = [".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java"]

    if exclude is None:
        exclude = [".git", "__pycache__", "node_modules", ".venv", "venv", "build", "dist"]

    results = []
    target: _Path = _Path(dir_path)

    if not target.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    for file_path in sorted(target.rglob("*")):
        # Skip excluded directories
        rel = file_path.relative_to(target)
        parts = rel.parts
        if any(part in exclude for part in parts):
            continue

        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in extensions:
            continue

        try:
            result = analyze_file(str(file_path))
            results.append(result)
        except Exception as e:
            results.append(
                AnalysisResult(
                    file_path=str(file_path),
                    scores=Score(total=0, grade="F"),
                    findings=[
                        Finding(
                            rule_id="ERR-002",
                            title="Analysis error",
                            description=str(e),
                            severity=Severity.INFO,
                            category=Category.INFO,
                        )
                    ],
                )
            )

    return results

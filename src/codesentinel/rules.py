"""Rule definitions for CodeSentinel analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from codesentinel.models import Category, Finding, Severity


@dataclass
class Rule:
    """A single analysis rule."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    pattern: str  # regex pattern to match
    flags: int = 0  # re.IGNORECASE, etc.
    suggestion: str = ""
    confidence: float = 1.0
    ai_pattern: bool = False  # True if this is a common AI-generated code pattern


# Core rules for detecting AI-generated code patterns and quality issues
CORE_RULES: List[Rule] = [
    # --- AI-generated code patterns ---
    Rule(
        rule_id="AI-001",
        title="Magic string literals for error messages",
        description="AI-generated code often uses hardcoded error messages. Consider using constants or i18n.",
        severity=Severity.LOW,
        category=Category.AI_PATTERNS,
        pattern=r'raise\s+\w+Error\s*\(\s*["\'][^"\']{50,}["\']',
        suggestion="Extract long error messages into named constants for maintainability.",
        confidence=0.8,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-002",
        title="Overly verbose try/except with bare except",
        description="Bare except clauses catch all exceptions including SystemExit and KeyboardInterrupt.",
        severity=Severity.HIGH,
        category=Category.BEST_PRACTICES,
        pattern=r'except\s*:',
        suggestion="Use specific exception types: 'except ValueError:' instead of bare 'except:'.",
        confidence=1.0,
    ),
    Rule(
        rule_id="AI-003",
        title="Global variable usage",
        description="AI-generated code frequently uses global variables instead of proper state management.",
        severity=Severity.MEDIUM,
        category=Category.AI_PATTERNS,
        pattern=r'^\s*global\s+\w+',
        flags=re.MULTILINE,
        suggestion="Use class state, dependency injection, or function parameters instead of globals.",
        confidence=0.7,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-004",
        title="Eval or exec usage",
        description="Use of eval/exec is a major security risk. AI often introduces these when building dynamic parsers.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        pattern=r'\b(eval|exec)\s*\(',
        suggestion="Use ast.literal_eval() for safe evaluation, or build a proper parser.",
        confidence=1.0,
    ),
    Rule(
        rule_id="AI-005",
        title="Hardcoded credentials or API keys",
        description="AI-generated code may include hardcoded secrets. Use environment variables instead.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        pattern=r'(?:password|secret|api_key|api_key|token|apikey)\s*=\s*["\'][^"\']{8,}["\']',
        flags=re.IGNORECASE,
        suggestion="Move secrets to environment variables or a secure vault.",
        confidence=0.85,
    ),
    Rule(
        rule_id="AI-006",
        title="SQL string concatenation",
        description="String concatenation in SQL queries is vulnerable to SQL injection.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        pattern=r'(?:execute|cursor)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*["\'].*%',
        flags=re.IGNORECASE,
        suggestion="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,)).",
        confidence=0.9,
    ),
    Rule(
        rule_id="AI-007",
        title="Subprocess with shell=True",
        description="shell=True is dangerous and enables command injection attacks.",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        pattern=r'subprocess\.\w+\(.*shell\s*=\s*True',
        suggestion="Use shell=False and pass arguments as a list.",
        confidence=1.0,
    ),
    Rule(
        rule_id="AI-008",
        title="Hardcoded file paths",
        description="AI-generated code often uses hardcoded absolute paths that won't work across systems.",
        severity=Severity.LOW,
        category=Category.AI_PATTERNS,
        pattern=r'(?:open|Path)\s*\(\s*["\'](?:\/|C:|D:)[^"\']*["\']',
        suggestion="Use os.path.join() or pathlib with relative paths and config files.",
        confidence=0.75,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-009",
        title="Missing input validation",
        description="AI-generated code often skips input validation on function parameters.",
        severity=Severity.MEDIUM,
        category=Category.QUALITY,
        pattern=r'def\s+\w+\([^)]*\):\s*\n(?:\s*"""[^"]*"""\s*\n)?\s*(?:assert|if\s+not|if\s+is\s+None|raise\s+ValueError)',
        flags=re.MULTILINE | re.DOTALL,
        suggestion="Add explicit input validation at the start of public functions.",
        confidence=0.6,
    ),
    Rule(
        rule_id="AI-010",
        title="Inefficient list comprehension in loop",
        description="Creating lists inside loops is inefficient. Consider using generators.",
        severity=Severity.LOW,
        category=Category.PERFORMANCE,
        pattern=r'for\s+\w+\s+in\s+range\([^)]*\):\s*\n\s*\w+\s*=\s*\[',
        flags=re.MULTILINE,
        suggestion="Use generators or pre-allocate lists for better memory efficiency.",
        confidence=0.7,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-011",
        title="Commented-out code blocks",
        description="Commented-out code suggests incomplete cleanup. AI often leaves debug code commented.",
        severity=Severity.INFO,
        category=Category.MAINTAINABILITY,
        pattern=r'^\s*#[^\n]*(?:TODO|FIXME|HACK|XXX|DEBUG|REVIEW|TEMP|WORKAROUND)',
        flags=re.MULTILINE,
        suggestion="Remove commented-out code or convert to proper TODO tracking.",
        confidence=0.9,
    ),
    Rule(
        rule_id="AI-012",
        title="Excessively long lines",
        description="Lines over 100 characters reduce readability.",
        severity=Severity.LOW,
        category=Category.MAINTAINABILITY,
        pattern=r'^.{101,}$',
        flags=re.MULTILINE,
        suggestion="Break long lines for better readability.",
        confidence=1.0,
    ),
    Rule(
        rule_id="AI-013",
        title="Use of 'any' or 'all' with generator without parentheses",
        description="AI sometimes writes 'any x for x in y' without proper generator syntax.",
        severity=Severity.MEDIUM,
        category=Category.QUALITY,
        pattern=r'(?:any|all)\s+\w+\s+for\s+\w+\s+in',
        suggestion="Use proper generator expression: 'any(x for x in y)'.",
        confidence=0.8,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-014",
        title="Missing error handling in file operations",
        description="File operations without try/except can crash on I/O errors.",
        severity=Severity.MEDIUM,
        category=Category.BEST_PRACTICES,
        pattern=r'(?:open|Path\.\w+\(|shutil\.\w+\()[^)]*\)\s*(?!.*(?:try|except))',
        flags=re.MULTILINE,
        suggestion="Wrap file operations in try/except blocks.",
        confidence=0.65,
    ),
    Rule(
        rule_id="AI-015",
        title="Unused imports",
        description="Imported modules that are never used add overhead and confusion.",
        severity=Severity.LOW,
        category=Category.MAINTAINABILITY,
        pattern=r'^\s*import\s+\w+(\s*,\s*\w+)*\s*$',
        flags=re.MULTILINE,
        suggestion="Remove unused imports to keep the codebase clean.",
        confidence=0.5,
    ),
    Rule(
        rule_id="AI-016",
        title="Use of 'pass' as sole statement",
        description="Standalone 'pass' often indicates incomplete implementation, common in AI scaffolding.",
        severity=Severity.INFO,
        category=Category.AI_PATTERNS,
        pattern=r'^\s*pass\s*$',
        flags=re.MULTILINE,
        suggestion="Implement the function or add a TODO comment explaining why it's empty.",
        confidence=0.7,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-017",
        title="Re-assigning function parameters",
        description="Reassigning parameters is confusing and often indicates AI-generated code that didn't think through the design.",
        severity=Severity.MEDIUM,
        category=Category.QUALITY,
        pattern=r'def\s+\w+\([^)]*\):\s*\n\s*\w+\s*=\s*',
        flags=re.MULTILINE,
        suggestion="Use a new variable name instead of reassigning the parameter.",
        confidence=0.75,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-018",
        title="Hardcoded timeouts or delays",
        description="Magic numbers for timeouts make code fragile and hard to configure.",
        severity=Severity.LOW,
        category=Category.BEST_PRACTICES,
        pattern=r'(?:time\.sleep|timeout|delay)\s*=\s*\d{2,}',
        suggestion="Extract magic numbers to named constants with documentation.",
        confidence=0.8,
    ),
    Rule(
        rule_id="AI-019",
        title="Use of 'print' for logging",
        description="Print statements should be replaced with proper logging for production code.",
        severity=Severity.LOW,
        category=Category.BEST_PRACTICES,
        pattern=r'\bprint\s*\(',
        suggestion="Use the logging module: import logging; logger = logging.getLogger(__name__).",
        confidence=0.9,
    ),
    Rule(
        rule_id="AI-020",
        title="XSS-vulnerable string formatting in HTML",
        description="Direct string interpolation into HTML is vulnerable to XSS attacks.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        pattern=r'(?:f["\']<[^>]*\{|html\(\s*["\'].*\{|\.format\s*\([^)]*\))[^"]*["\']',
        flags=re.IGNORECASE,
        suggestion="Use a templating engine with auto-escaping (Jinja2) or sanitize output.",
        confidence=0.7,
    ),
    Rule(
        rule_id="AI-021",
        title="Missing type hints on public functions",
        description="Public functions without type hints reduce code maintainability.",
        severity=Severity.INFO,
        category=Category.MAINTAINABILITY,
        pattern=r'def\s+(?:[a-z_]+\w*)\s*\([^)]*\)\s*->\s*\w+[^:]*:\s*\n(?!\s*"""|^\s*#)',
        flags=re.MULTILINE,
        suggestion="Add type hints to improve code documentation and IDE support.",
        confidence=0.6,
    ),
    Rule(
        rule_id="AI-022",
        title="Nested try/except blocks",
        description="Deeply nested exception handling is hard to read and maintain.",
        severity=Severity.MEDIUM,
        category=Category.QUALITY,
        pattern=r'try:\s*\n\s*try:\s*\n\s*except',
        flags=re.MULTILINE | re.DOTALL,
        suggestion="Flatten nested exception handling using helper functions.",
        confidence=0.75,
        ai_pattern=True,
    ),
    Rule(
        rule_id="AI-023",
        title="Use of 'isinstance' with tuple of types for duck typing",
        description="Overuse of isinstance checks can indicate a lack of duck typing.",
        severity=Severity.LOW,
        category=Category.QUALITY,
        pattern=r'isinstance\s*\([^)]*,\s*\([^)]+\)\s*\)',
        suggestion="Consider duck typing or protocol/ABC patterns instead.",
        confidence=0.6,
    ),
    Rule(
        rule_id="AI-024",
        title="Mutable default argument",
        description="Mutable default arguments (lists, dicts) are shared across calls.",
        severity=Severity.HIGH,
        category=Category.BEST_PRACTICES,
        pattern=r'def\s+\w+\([^)]*=\s*(?:\[|\{|set\(|dict\()',
        suggestion="Use None as default and initialize inside the function.",
        confidence=1.0,
    ),
    Rule(
        rule_id="AI-025",
        title="Excessively long functions",
        description="Functions over 50 lines are hard to understand and maintain.",
        severity=Severity.MEDIUM,
        category=Category.MAINTAINABILITY,
        pattern=r'def\s+\w+\([^)]*\):\s*\n(?:[^\n]*\n){50,}',
        flags=re.MULTILINE,
        suggestion="Break this function into smaller, focused helper functions.",
        confidence=0.7,
        ai_pattern=True,
    ),
]


def get_rules() -> List[Rule]:
    """Return the list of all analysis rules."""
    return list(CORE_RULES)


def get_rules_by_category(category: Category) -> List[Rule]:
    """Return rules filtered by category."""
    return [r for r in CORE_RULES if r.category == category]


def get_rules_by_severity(severity: Severity) -> List[Rule]:
    """Return rules filtered by severity."""
    return [r for r in CORE_RULES if r.severity == severity]


def get_rules_for_language(language: str) -> List[Rule]:
    """Return rules applicable to a specific language."""
    # For now, all rules apply to Python. This can be extended for other languages.
    if language == "python":
        return CORE_RULES
    return []

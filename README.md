# README.md

# CodeSentinel

**AI-generated code quality and security scanner.**

Detects security vulnerabilities, quality issues, and AI-generated code patterns in your codebase. Get a graded report with actionable suggestions — before your AI-generated code hits production.

## Features

- **25+ analysis rules** covering security, quality, maintainability, and AI patterns
- **AST-based analysis** for Python-specific issues (mutable defaults, function length)
- **Security scanning** for eval/exec, hardcoded secrets, SQL injection, shell injection, unsafe pickle, weak hashing
- **AI pattern detection** — spots common AI-generated code anti-patterns
- **Graded reports** — A through F scoring with category breakdowns
- **Multiple output formats** — text (terminal), JSON (CI), Markdown (docs)
- **CLI tool** — `codesentinel scan`, `codesentinel rules`, `codesentinel sample-config`
- **Zero external dependencies** for core functionality

## Install

```bash
pip install codesentinel
```

Or from source:

```bash
git clone https://github.com/EdgarOrtegaRamirez/codesentinel.git
cd codesentinel
pip install -e .
```

## Quick Start

```bash
# Scan a file
codesentinel scan main.py

# Scan a directory
codesentinel scan src/

# JSON output for CI
codesentinel scan . --format json

# Markdown report
codesentinel scan . -o report.md --format markdown

# List available rules
codesentinel rules --category security
codesentinel rules --severity critical
```

## Example Output

```
========================================================================
  CodeSentinel - AI Code Quality Report
========================================================================

📄 sample_code.py
   Language: python | Lines: 43
   Grade: D | Score: 66.9/100
   Status: ✅ PASSING

   ┌─────────────────────┬────────┬──────────────────┐
   │ Category            │ Score  │ Status           │
   ├─────────────────────┼────────┼──────────────────┤
   │ Security            │   19.0 │ ❌            │
   │ Quality             │   88.0 │ ✅            │
   │ Maintainability     │   84.0 │ ✅            │
   │ Performance         │   98.0 │ ✅            │
   │ AI Quality          │   96.0 │ ✅            │
   └─────────────────────┴────────┴──────────────────┘

   🔴 CRITICAL (3):
     • [AI-004] Eval or exec usage (line 50)
       → Use ast.literal_eval() for safe evaluation.
     • [AI-005] Hardcoded credentials (line 55)
       → Move secrets to environment variables.
     • [AI-005] Hardcoded credentials (line 56)
       → Move secrets to environment variables.

   📊 SUMMARY
   Files analyzed: 1
   Total findings: 30
   Critical: 3 | High: 5 | Medium: 8 | Low: 9
   Average score: 66.9/100
========================================================================
```

## Analysis Rules

### Security Rules

| Rule ID  | Issue | Severity |
|----------|-------|----------|
| AI-004 | eval() / exec() usage | Critical |
| AI-005 | Hardcoded credentials | Critical |
| AI-006 | SQL string concatenation | Critical |
| AI-007 | subprocess with shell=True | High |
| SEC-001 | Unsafe pickle usage | High |
| SEC-002 | os.system() command injection | High |
| SEC-003 | tempfile.mktemp() race condition | Medium |
| SEC-004 | Weak hashing (MD5/SHA1) | High |

### AI Pattern Rules

| Rule ID  | Issue | Severity |
|----------|-------|----------|
| AI-001 | Magic string literals | Low |
| AI-002 | Bare except clauses | High |
| AI-003 | Global variable usage | Medium |
| AI-008 | Hardcoded file paths | Low |
| AI-010 | Inefficient loops | Low |
| AI-016 | Standalone pass statements | Info |
| AI-017 | Reassigning parameters | Medium |
| AI-022 | Nested try/except | Medium |
| AI-025 | Excessively long functions | Medium |

### Quality Rules

| Rule ID  | Issue | Severity |
|----------|-------|----------|
| AI-009 | Missing input validation | Medium |
| AI-012 | Excessively long lines | Low |
| AI-014 | Missing error handling | Medium |
| AI-015 | Unused imports | Low |
| AI-018 | Hardcoded timeouts | Low |
| AI-019 | Print instead of logging | Low |
| AI-020 | XSS-vulnerable HTML | Critical |
| AI-021 | Missing type hints | Info |
| AI-023 | Overuse of isinstance | Low |
| AI-024 | Mutable default arguments | High |

## CLI Reference

```
codesentinel <command> [options]

Commands:
  scan          Scan code for quality issues
  rules         List available analysis rules
  sample-config Generate a sample configuration file

Scan Options:
  --format, -f      Output format: text, json, markdown (default: text)
  --output, -o      Output file path
  --fail-on-severity  Fail CI if findings at this severity or above
  --quiet, -q       Suppress output on success
```

## Architecture

```
codesentinel/
├── src/codesentinel/
│   ├── __init__.py     — Package version
│   ├── models.py       — Data classes (Finding, Score, AnalysisResult)
│   ├── rules.py        — 25+ analysis rules with regex patterns
│   ├── analyzer.py     — Core engine (regex + AST analysis)
│   ├── report.py       — Text/JSON/Markdown report generators
│   └── cli.py          — CLI entry point
├── tests/              — 81 tests
├── pyproject.toml      — Build config
└── README.md
```

## Testing

```bash
pip install pytest
pytest tests/ -v
```

81 tests covering models, rules, analyzer, and reports.

## License

MIT — see [LICENSE](LICENSE) for details.

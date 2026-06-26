# CodeSentinel — AGENTS.md

## For AI Coding Agents

This file contains notes for AI agents that interact with this project.

### What is CodeSentinel?

CodeSentinel is an AI-generated code quality and security scanner. It detects common
AI-generated code patterns (hardcoded secrets, eval/exec, shell injection, bare except,
etc.), analyzes code quality, and produces graded reports.

### Architecture

```
codesentinel/
├── src/codesentinel/
│   ├── __init__.py     — Package version
│   ├── models.py       — Data classes (Finding, Score, AnalysisResult)
│   ├── rules.py        — 25+ analysis rules with regex patterns
│   ├── analyzer.py     — Core engine (regex + AST analysis)
│   ├── report.py       — Text/JSON/Markdown report generators
│   └── cli.py          — CLI entry point (argparse)
├── tests/              — 81 tests across 4 modules
├── sample_code.py      — Intentionally dirty sample for testing
├── pyproject.toml      — Build config (hatchling)
├── .gitignore
└── README.md
```

### Key design decisions

1. **Regex-first, AST-second**: Most rules are regex-based for speed and broad language
   support. AST analysis is used only for Python-specific checks (mutable defaults,
   function length).
2. **Scoring system**: Each category starts at 100, deductions are weighted by severity.
   Final grade is A-F based on weighted average.
3. **No external dependencies required**: Core functionality requires only stdlib. Optional
   deps (rich, pyyaml) enhance CLI UX.
4. **Non-destructive**: CodeSentinel reads files only — never writes or modifies source.

### Adding new rules

1. Add a `Rule` entry to `CORE_RULES` in `src/codesentinel/rules.py`
2. If it requires AST analysis, add logic to `_detect_ast_issues()` in `analyzer.py`
3. If it's language-specific, add to `_check_security_patterns()` or a new function
4. Add tests in `tests/test_rules.py` or `tests/test_analyzer.py`
5. Update `sample_code.py` with code that triggers the new rule

### CLI usage

```bash
# Basic scan
codesentinel scan /path/to/code

# JSON output for CI
codesentinel scan . --format json

# Save report
codesentinel scan . -o report.md --format markdown

# List rules
codesentinel rules --category security
codesentinel rules --severity critical
codesentinel rules --json
```

### CI integration

```yaml
# In .github/workflows/ci.yml
- name: Run CodeSentinel
  run: |
    pip install codesentinel
    codesentinel scan src/ --format json --output codesentinel-report.json
```

### Testing

```bash
pytest tests/ -v
```

All 81 tests must pass before committing.

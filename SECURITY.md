# Security

## Security Policy

CodeSentinel is a static analysis tool — it reads source code files and produces reports.
It never modifies, executes, or transmits your code.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

### Reporting a Vulnerability

Please report security vulnerabilities via GitHub Issues with the "Security" label.
Include steps to reproduce and expected vs. actual behavior.

### What CodeSentinel Checks

CodeSentinel detects the following security issues in Python code:

| Rule ID   | Issue                          | Severity |
|-----------|--------------------------------|----------|
| AI-004    | eval() / exec() usage          | Critical |
| AI-005    | Hardcoded credentials          | Critical |
| AI-006    | SQL injection                  | Critical |
| AI-007    | subprocess with shell=True     | High     |
| SEC-001   | Unsafe pickle deserialization  | High     |
| SEC-002   | os.system() command injection  | High     |
| SEC-003   | tempfile.mktemp() race condition | Medium |
| SEC-004   | Weak hashing (MD5/SHA1)        | High     |

### Best Practices

1. **Run before committing**: Integrate CodeSentinel into your pre-commit hooks.
2. **Fix critical issues first**: Critical and High findings should never be committed.
3. **Review Medium findings**: Medium findings should be reviewed and addressed.
4. **Use the JSON output**: For CI/CD integration, use `--format json`.

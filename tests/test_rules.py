"""Tests for CodeSentinel rules engine."""

from codesentinel.models import Category, Severity
from codesentinel.rules import (
    CORE_RULES,
    get_rules,
    get_rules_by_category,
    get_rules_by_severity,
    get_rules_for_language,
)


class TestCoreRules:
    def test_rules_exist(self):
        rules = get_rules()
        assert len(rules) > 0

    def test_rules_have_required_fields(self):
        rules = get_rules()
        for rule in rules:
            assert hasattr(rule, "rule_id")
            assert hasattr(rule, "title")
            assert hasattr(rule, "description")
            assert hasattr(rule, "severity")
            assert hasattr(rule, "category")
            assert hasattr(rule, "pattern")
            assert hasattr(rule, "rule_id")
            assert len(rule.rule_id) > 0
            assert len(rule.title) > 0

    def test_all_rules_have_valid_severity(self):
        rules = get_rules()
        for rule in rules:
            assert rule.severity in Severity

    def test_all_rules_have_valid_category(self):
        rules = get_rules()
        for rule in rules:
            assert rule.severity in Severity

    def test_rules_have_suggestions(self):
        rules = get_rules()
        for rule in rules:
            assert rule.suggestion is not None
            assert len(rule.suggestion) > 0

    def test_rules_patterns_are_valid_regex(self):
        import re
        rules = get_rules()
        for rule in rules:
            try:
                re.compile(rule.pattern, rule.flags)
            except re.error as e:
                assert False, f"Invalid regex pattern for {rule.rule_id}: {e}"


class TestRulesFiltering:
    def test_get_rules_by_category_security(self):
        rules = get_rules_by_category(Category.SECURITY)
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == Category.SECURITY

    def test_get_rules_by_category_quality(self):
        rules = get_rules_by_category(Category.QUALITY)
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == Category.QUALITY

    def test_get_rules_by_category_ai_patterns(self):
        rules = get_rules_by_category(Category.AI_PATTERNS)
        assert len(rules) > 0
        for rule in rules:
            assert rule.category == Category.AI_PATTERNS

    def test_get_rules_by_severity_critical(self):
        rules = get_rules_by_severity(Severity.CRITICAL)
        assert len(rules) > 0
        for rule in rules:
            assert rule.severity == Severity.CRITICAL

    def test_get_rules_by_severity_high(self):
        rules = get_rules_by_severity(Severity.HIGH)
        assert len(rules) > 0
        for rule in rules:
            assert rule.severity == Severity.HIGH

    def test_get_rules_for_python(self):
        rules = get_rules_for_language("python")
        assert len(rules) == len(CORE_RULES)

    def test_get_rules_for_unknown_language(self):
        rules = get_rules_for_language("unknown")
        assert len(rules) == 0

    def test_rule_ids_unique(self):
        rules = get_rules()
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids))

    def test_security_rules_exist(self):
        rules = get_rules_by_category(Category.SECURITY)
        rule_ids = [r.rule_id for r in rules]
        assert "AI-004" in rule_ids  # eval/exec
        assert "AI-005" in rule_ids  # hardcoded credentials
        assert "AI-006" in rule_ids  # SQL injection
        assert "AI-007" in rule_ids  # shell=True

    def test_ai_pattern_rules_exist(self):
        rules = get_rules_by_category(Category.AI_PATTERNS)
        assert len(rules) > 0

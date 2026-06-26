"""Models for CodeSentinel analysis results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


class Severity(enum.Enum):
    """Severity level of a finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(enum.Enum):
    """Category of a code issue."""
    SECURITY = "security"
    QUALITY = "quality"
    AI_PATTERNS = "ai_patterns"
    MAINTAINABILITY = "maintainability"
    PERFORMANCE = "performance"
    BEST_PRACTICES = "best_practices"
    INFO = "info"


@dataclass
class Finding:
    """A single finding from code analysis."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    line: Optional[int] = None
    column: Optional[int] = None
    suggestion: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    code_snippet: str = ""
    ai_pattern: bool = False

    @property
    def is_blocking(self) -> bool:
        """Whether this finding should block merging."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "line": self.line,
            "column": self.column,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "code_snippet": self.code_snippet,
            "ai_pattern": self.ai_pattern,
        }


@dataclass
class Score:
    """Overall quality score for analyzed code."""
    total: float = 100.0
    security: float = 100.0
    quality: float = 100.0
    maintainability: float = 100.0
    performance: float = 100.0
    ai_quality: float = 100.0
    num_findings: int = 0
    num_critical: int = 0
    num_high: int = 0
    num_medium: int = 0
    num_low: int = 0

    @property
    def grade(self) -> str:
        """Letter grade based on total score."""
        if self.total >= 90:
            return "A"
        elif self.total >= 80:
            return "B"
        elif self.total >= 70:
            return "C"
        elif self.total >= 60:
            return "D"
        else:
            return "F"

    @property
    def is_passing(self) -> bool:
        """Whether the code passes the quality threshold."""
        return self.total >= 60

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "total": round(self.total, 1),
            "security": round(self.security, 1),
            "quality": round(self.quality, 1),
            "maintainability": round(self.maintainability, 1),
            "performance": round(self.performance, 1),
            "ai_quality": round(self.ai_quality, 1),
            "grade": self.grade,
            "num_findings": self.num_findings,
            "num_critical": self.num_critical,
            "num_high": self.num_high,
            "num_medium": self.num_medium,
            "num_low": self.num_low,
            "is_passing": self.is_passing,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result for a file or directory."""
    file_path: str
    scores: Score
    findings: List[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    language: str = ""
    line_count: int = 0

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "file_path": self.file_path,
            "scores": self.scores.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "language": self.language,
            "line_count": self.line_count,
        }

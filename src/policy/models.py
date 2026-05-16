"""Policy models for Agent Firewall."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern


class Severity(str, Enum):  # noqa: UP042
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order[self.value] < order[other.value]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order[self.value] > order[other.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self > other


@dataclass
class ContentPattern:
    name: str
    pattern: str
    severity: Severity
    compiled: Pattern[str] = field(init=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern)


@dataclass
class SequenceStep:
    action: str
    condition: str


@dataclass
class SuspiciousSequence:
    name: str
    pattern: list[SequenceStep]
    severity: Severity


@dataclass
class FilePolicy:
    blocked_read_paths: list[str] = field(default_factory=list)
    blocked_read_patterns: list[str] = field(default_factory=list)
    allowed_read_paths: list[str] = field(default_factory=list)
    allowed_write_paths: list[str] = field(default_factory=list)


@dataclass
class NetworkPolicy:
    trusted_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)
    scrutinize_methods: list[str] = field(default_factory=list)
    max_fetch_size: int = 1_048_576


@dataclass
class CommandPolicy:
    blocked_patterns: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)


@dataclass
class ContentInspectionPolicy:
    enabled: bool = True
    sensitive_content_patterns: list[ContentPattern] = field(default_factory=list)


@dataclass
class CorrelationPolicy:
    window_seconds: int = 30
    suspicious_sequences: list[SuspiciousSequence] = field(default_factory=list)


@dataclass
class AlertPolicy:
    log_file: str = "agent_firewall.log"
    desktop_notify: bool = True
    webhook_url: str = ""
    min_severity: Severity = Severity.MEDIUM


@dataclass
class FirewallPolicy:
    files: FilePolicy = field(default_factory=FilePolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    commands: CommandPolicy = field(default_factory=CommandPolicy)
    content_inspection: ContentInspectionPolicy = field(default_factory=ContentInspectionPolicy)
    correlation: CorrelationPolicy = field(default_factory=CorrelationPolicy)
    alerts: AlertPolicy = field(default_factory=AlertPolicy)

"""Content inspection and analysis for Agent Firewall."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.detection.patterns import (
    INJECTION_PATTERN_DETECTOR,
    SENSITIVE_PATH_DETECTOR,
    DetectionPattern,
)
from src.policy.engine import PolicyEngine
from src.policy.models import ContentPattern, Severity


class ActionType(str, Enum):  # noqa: UP042
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    HTTP_REQUEST = "http_request"
    EXECUTE_COMMAND = "execute_command"
    WEB_FETCH = "web_fetch"


class ActionDecision(str, Enum):  # noqa: UP042
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    QUARANTINE = "quarantine"


@dataclass
class ActionRequest:
    action: ActionType
    target: str
    method: str | None = None
    content: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ActionResult:
    decision: ActionDecision
    reason: str
    severity: Severity
    findings: list[str] = field(default_factory=list)
    blocked_content_summary: str = ""

    @property
    def is_blocked(self) -> bool:
        return self.decision in (ActionDecision.BLOCK, ActionDecision.QUARANTINE)

    @property
    def is_flagged(self) -> bool:
        return self.decision == ActionDecision.FLAG


@dataclass
class InspectionResult:
    content_findings: list[tuple[ContentPattern, str]]
    injection_findings: list[tuple[DetectionPattern, str]]
    path_sensitive: bool
    path_reason: str = ""


class ContentInspector:
    """Inspects content and actions for security threats."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy = policy_engine

    def inspect_action(self, request: ActionRequest) -> list[ActionResult]:
        results = []

        match request.action:
            case ActionType.READ_FILE:
                result = self._inspect_file_read(request)
                if result:
                    results.append(result)
            case ActionType.WRITE_FILE:
                result = self._inspect_file_write(request)
                if result:
                    results.append(result)
            case ActionType.HTTP_REQUEST:
                result = self._inspect_http_request(request)
                if result:
                    results.append(result)
            case ActionType.EXECUTE_COMMAND:
                result = self._inspect_command(request)
                if result:
                    results.append(result)
            case ActionType.WEB_FETCH:
                result = self._inspect_web_fetch(request)
                if result:
                    results.append(result)

        return (
            results
            if results
            else [
                ActionResult(
                    decision=ActionDecision.ALLOW,
                    reason="No threats detected",
                    severity=Severity.LOW,
                )
            ]
        )

    def inspect_content(self, content: str) -> InspectionResult:
        content_findings = self._policy.inspect_content(content)
        injection_findings = INJECTION_PATTERN_DETECTOR.scan(content)
        return InspectionResult(
            content_findings=content_findings,
            injection_findings=injection_findings,
            path_sensitive=False,
        )

    def _inspect_file_read(self, request: ActionRequest) -> ActionResult | None:
        if self._policy.is_file_read_blocked(request.target):
            findings = []
            if SENSITIVE_PATH_DETECTOR.is_sensitive(request.target):
                findings.append("Matches sensitive path pattern")
            findings.append("Path is in blocked list")

            return ActionResult(
                decision=ActionDecision.BLOCK,
                reason=f"File read blocked: {request.target}",
                severity=Severity.CRITICAL,
                findings=findings,
            )

        return None

    def _inspect_file_write(self, request: ActionRequest) -> ActionResult | None:
        if request.content:
            findings = self._policy.inspect_content(request.content)
            if findings:
                detail_findings = [f"Contains: {pat.name}" for pat, _ in findings]
                return ActionResult(
                    decision=ActionDecision.FLAG,
                    reason=f"Write contains potentially sensitive content: {request.target}",
                    severity=next((f[0].severity for f in findings), Severity.MEDIUM),
                    findings=detail_findings,
                )
        return None

    def _inspect_http_request(self, request: ActionRequest) -> ActionResult | None:
        from urllib.parse import urlparse

        parsed = urlparse(request.target)
        domain = parsed.hostname or ""

        if self._policy.is_domain_blocked(domain):
            return ActionResult(
                decision=ActionDecision.BLOCK,
                reason=f"Domain blocked: {domain}",
                severity=Severity.CRITICAL,
                findings=[f"Domain {domain} is in blocked list"],
            )

        if (
            request.method
            and self._policy.needs_content_inspection(request.method)
            and request.content
        ):
            content_findings = self._policy.inspect_content(request.content)
            if content_findings:
                detail_findings = [f"Body contains: {pat.name}" for pat, _ in content_findings]
                severity = max((f[0].severity for f in content_findings), key=lambda s: s.value)
                return ActionResult(
                    decision=ActionDecision.BLOCK,
                    reason=f"Request body contains sensitive content to {domain}",
                    severity=severity,
                    findings=detail_findings,
                )

        if not self._policy.is_domain_trusted(domain) and request.method in (
            "POST",
            "PUT",
            "PATCH",
        ):
            return ActionResult(
                decision=ActionDecision.FLAG,
                reason=f"Untrusted domain with write method: {domain}",
                severity=Severity.MEDIUM,
                findings=[f"Domain {domain} is not in trusted list"],
            )

        return None

    def _inspect_command(self, request: ActionRequest) -> ActionResult | None:
        if self._policy.is_command_blocked(request.target):
            return ActionResult(
                decision=ActionDecision.BLOCK,
                reason=f"Command blocked by policy: {request.target[:100]}",
                severity=Severity.CRITICAL,
                findings=["Command matches blocked pattern"],
            )

        if self._policy.command_needs_approval(request.target):
            return ActionResult(
                decision=ActionDecision.FLAG,
                reason=f"Command requires approval: {request.target[:100]}",
                severity=Severity.HIGH,
                findings=["Command requires user approval"],
            )

        sensitive_check = SENSITIVE_PATH_DETECTOR.is_sensitive(request.target)
        if sensitive_check:
            return ActionResult(
                decision=ActionDecision.FLAG,
                reason=f"Command references sensitive path: {request.target[:100]}",
                severity=Severity.HIGH,
                findings=["Command references sensitive file/path"],
            )

        return None

    def _inspect_web_fetch(self, request: ActionRequest) -> ActionResult | None:
        if request.content:
            injection_findings = INJECTION_PATTERN_DETECTOR.scan(request.content)
            if injection_findings:
                max_severity = max(
                    (f[0].severity for f in injection_findings), key=lambda s: s.value
                )
                detail_findings = [f"Injection: {pat.name}" for pat, _ in injection_findings]
                return ActionResult(
                    decision=ActionDecision.FLAG,
                    reason=f"Fetched content contains potential injection from {request.target}",
                    severity=max_severity,
                    findings=detail_findings,
                )

        return None

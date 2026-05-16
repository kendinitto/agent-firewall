"""Policy engine - loads and evaluates firewall rules."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from re import Pattern

import yaml

from src.policy.models import (
    AlertPolicy,
    CommandPolicy,
    ContentInspectionPolicy,
    ContentPattern,
    CorrelationPolicy,
    FilePolicy,
    FirewallPolicy,
    NetworkPolicy,
    SequenceStep,
    Severity,
    SuspiciousSequence,
)


class PolicyEngine:
    """Loads policy from YAML and provides fast lookup methods."""

    def __init__(self, policy: FirewallPolicy) -> None:
        self.policy = policy
        self._blocked_patterns_compiled: list[Pattern[str]] = []
        self._command_blocked_compiled: list[Pattern[str]] = []
        self._blocked_read_patterns_fnmatch: list[str] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        for pat in self.policy.content_inspection.sensitive_content_patterns:
            pat.compiled
        for pat in self.policy.commands.blocked_patterns:
            self._command_blocked_compiled.append(re.compile(pat))

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        path = Path(path)
        with open(path) as f:
            raw = yaml.safe_load(f)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> PolicyEngine:
        files_raw = raw.get("files", {})
        network_raw = raw.get("network", {})
        commands_raw = raw.get("commands", {})
        content_raw = raw.get("content_inspection", {})
        correlation_raw = raw.get("correlation", {})
        alerts_raw = raw.get("alerts", {})

        sensitive_patterns = []
        for p in content_raw.get("sensitive_content_patterns", []):
            sensitive_patterns.append(
                ContentPattern(
                    name=p["name"],
                    pattern=p["pattern"],
                    severity=Severity(p["severity"]),
                )
            )

        suspicious_sequences = []
        for s in correlation_raw.get("suspicious_sequences", []):
            steps = []
            for step in s["pattern"]:
                steps.append(SequenceStep(action=step["action"], condition=step["condition"]))
            suspicious_sequences.append(
                SuspiciousSequence(
                    name=s["name"],
                    pattern=steps,
                    severity=Severity(s["severity"]),
                )
            )

        policy = FirewallPolicy(
            files=FilePolicy(
                blocked_read_paths=files_raw.get("blocked_read_paths", []),
                blocked_read_patterns=files_raw.get("blocked_read_patterns", []),
                allowed_read_paths=files_raw.get("allowed_read_paths", []),
                allowed_write_paths=files_raw.get("allowed_write_paths", []),
            ),
            network=NetworkPolicy(
                trusted_domains=network_raw.get("trusted_domains", []),
                blocked_domains=network_raw.get("blocked_domains", []),
                scrutinize_methods=network_raw.get("scrutinize_methods", []),
                max_fetch_size=network_raw.get("max_fetch_size", 1_048_576),
            ),
            commands=CommandPolicy(
                blocked_patterns=commands_raw.get("blocked_patterns", []),
                approval_required=commands_raw.get("approval_required", []),
            ),
            content_inspection=ContentInspectionPolicy(
                enabled=content_raw.get("enabled", True),
                sensitive_content_patterns=sensitive_patterns,
            ),
            correlation=CorrelationPolicy(
                window_seconds=correlation_raw.get("window_seconds", 30),
                suspicious_sequences=suspicious_sequences,
            ),
            alerts=AlertPolicy(
                log_file=alerts_raw.get("log_file", "agent_firewall.log"),
                desktop_notify=alerts_raw.get("desktop_notify", True),
                webhook_url=alerts_raw.get("webhook_url", ""),
                min_severity=Severity(alerts_raw.get("min_severity", "medium")),
            ),
        )
        return cls(policy)

    def is_file_read_blocked(self, filepath: str) -> bool:
        resolved = str(Path(filepath).expanduser().resolve())

        for blocked in self.policy.files.blocked_read_paths:
            blocked_resolved = str(Path(blocked).expanduser().resolve())
            if resolved.startswith(blocked_resolved):
                return True

        basename = os.path.basename(filepath)
        for pattern in self.policy.files.blocked_read_patterns:
            if fnmatch.fnmatch(basename, pattern):
                return True

        if self.policy.files.blocked_read_patterns:
            for pattern in self.policy.files.blocked_read_patterns:
                if fnmatch.fnmatch(filepath, pattern) or fnmatch.fnmatch(resolved, pattern):
                    return True

        return False

    def is_domain_blocked(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        for blocked in self.policy.network.blocked_domains:
            if domain == blocked.lower() or domain.endswith("." + blocked.lower()):
                return True
        return False

    def is_domain_trusted(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        for trusted in self.policy.network.trusted_domains:
            if domain == trusted.lower():
                return True
        return False

    def needs_content_inspection(self, method: str) -> bool:
        if not self.policy.content_inspection.enabled:
            return False
        return method.upper() in self.policy.network.scrutinize_methods

    def inspect_content(self, content: str) -> list[tuple[ContentPattern, str]]:
        if not self.policy.content_inspection.enabled:
            return []
        findings = []
        for pattern in self.policy.content_inspection.sensitive_content_patterns:
            match = pattern.compiled.search(content)
            if match:
                findings.append((pattern, match.group()))
        return findings

    def is_command_blocked(self, command: str) -> bool:
        for pattern in self.policy.commands.blocked_patterns:
            if re.search(pattern, command):
                return True
        return False

    def command_needs_approval(self, command: str) -> bool:
        for pattern in self.policy.commands.approval_required:
            if pattern in command:
                return True
        return False

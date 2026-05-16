"""Middleware for fast-path filtering."""

from __future__ import annotations

import re
from re import Pattern

from src.detection.patterns import SENSITIVE_PATH_DETECTOR
from src.policy.engine import PolicyEngine


class FastPathFilter:
    """Ultra-fast pre-filter for common cases. Runs before full inspection."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy = policy_engine
        self._compiled_block_patterns: list[tuple[str, Pattern[str]]] = []
        self._compile_fast_patterns()

    def _compile_fast_patterns(self) -> None:
        for path in self._policy.policy.files.blocked_read_paths:
            expanded = path.replace("~", str(__import__("os").path.expanduser("~")))
            self._compiled_block_patterns.append((expanded, re.compile(re.escape(expanded))))

    def check_file_read(self, filepath: str) -> tuple[bool, str] | None:
        if SENSITIVE_PATH_DETECTOR.is_sensitive(filepath):
            return (True, "sensitive_path")

        if self._policy.is_file_read_blocked(filepath):
            return (True, "blocked_path")

        return None

    def check_domain(self, domain: str) -> tuple[bool, str] | None:
        if self._policy.is_domain_blocked(domain):
            return (True, "blocked_domain")

        if self._policy.is_domain_trusted(domain):
            return (False, "trusted_domain")

        return None

    def check_command(self, command: str) -> tuple[bool, str] | None:
        if self._policy.is_command_blocked(command):
            return (True, "blocked_command")

        if SENSITIVE_PATH_DETECTOR.is_sensitive(command):
            return (True, "sensitive_in_command")

        return None

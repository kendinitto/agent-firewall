"""User feedback system for refining firewall rules."""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path
from typing import Any


class FeedbackStore:
    """Stores and applies user feedback on blocked/flagged actions."""

    def __init__(self, feedback_file: str = "feedback.json") -> None:
        self._path = Path(feedback_file)
        self._overrides: dict[str, Any] = {
            "allowed_paths": [],
            "allowed_domains": [],
            "allowed_commands": [],
            "decisions": [],
        }
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            with open(self._path) as f:
                self._overrides = json.load(f)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._overrides, f, indent=2)

    def add_path_allow(self, filepath: str) -> None:
        if filepath not in self._overrides["allowed_paths"]:
            self._overrides["allowed_paths"].append(filepath)
            self._save()

    def add_domain_allow(self, domain: str) -> None:
        if domain not in self._overrides["allowed_domains"]:
            self._overrides["allowed_domains"].append(domain)
            self._save()

    def add_decision(
        self,
        action: str,
        target: str,
        original_decision: str,
        user_decision: str,
        reason: str = "",
    ) -> None:
        from datetime import datetime

        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target,
            "original_decision": original_decision,
            "user_decision": user_decision,
            "reason": reason,
        }
        self._overrides["decisions"].append(entry)
        self._save()

    def get_overrides(self) -> dict[str, Any]:
        return self._overrides

    def is_path_overridden_allow(self, filepath: str) -> bool:
        return filepath in self._overrides["allowed_paths"]

    def is_domain_overridden_allow(self, domain: str) -> bool:
        return domain in self._overrides["allowed_domains"]

"""Alert logging for Agent Firewall."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from src.policy.models import Severity

logger = logging.getLogger("agent_firewall.alerts")


class AlertLogger:
    """Logs firewall actions to structured JSON log file."""

    def __init__(
        self, log_file: str = "agent_firewall.log", min_severity: Severity = Severity.MEDIUM
    ) -> None:
        self._log_file = Path(log_file)
        self._min_severity = min_severity
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        action: str,
        target: str,
        decision: str,
        severity: Severity,
        reason: str,
        details: dict | None = None,
    ) -> None:
        if severity < self._min_severity:
            return

        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target[:500],
            "decision": decision,
            "severity": severity.value,
            "reason": reason,
            "details": details or {},
        }

        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        log_level = (
            logging.ERROR if severity in (Severity.CRITICAL, Severity.HIGH) else logging.INFO
        )
        logger.log(log_level, "[%s] %s: %s — %s", severity.value.upper(), decision, action, reason)

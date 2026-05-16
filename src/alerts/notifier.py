"""Desktop notification support for Agent Firewall alerts."""

from __future__ import annotations

import logging
import subprocess

from src.policy.models import Severity

logger = logging.getLogger("agent_firewall.alerts")


class Notifier:
    """Sends desktop notifications for blocked/flagged actions."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    def notify(self, title: str, message: str, severity: Severity = Severity.MEDIUM) -> None:
        if not self._enabled:
            return

        if severity not in (Severity.HIGH, Severity.CRITICAL):
            return

        self._send_notification(title, message)

    def _send_notification(self, title: str, message: str) -> None:
        try:
            urgency = "critical" if "CRITICAL" in title else "normal"
            subprocess.run(
                ["notify-send", "-u", urgency, title, message],
                check=False,
                timeout=5,
            )
        except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
            logger.debug("Could not send desktop notification")

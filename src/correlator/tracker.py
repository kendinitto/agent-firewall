"""Action sequence tracker for correlating suspicious multi-step patterns."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from src.detection.patterns import SENSITIVE_PATH_DETECTOR
from src.policy.models import Severity


@dataclass
class TrackedAction:
    timestamp: float
    action_type: str
    target: str
    metadata: dict = field(default_factory=dict)


@dataclass
class SequenceMatch:
    sequence_name: str
    matched_actions: list[TrackedAction]
    severity: Severity


class ActionTracker:
    """Tracks actions per session and detects suspicious sequences."""

    def __init__(self, window_seconds: int = 30, max_actions: int = 100) -> None:
        self._sessions: dict[str, deque[TrackedAction]] = defaultdict(
            lambda: deque(maxlen=max_actions)
        )
        self._window = window_seconds

    def record(
        self, session_id: str, action_type: str, target: str, metadata: dict | None = None
    ) -> None:
        action = TrackedAction(
            timestamp=time.time(),
            action_type=action_type,
            target=target,
            metadata=metadata or {},
        )
        self._sessions[session_id].append(action)
        self._prune_old(session_id)

    def _prune_old(self, session_id: str) -> None:
        cutoff = time.time() - self._window
        session = self._sessions[session_id]
        while session and session[0].timestamp < cutoff:
            session.popleft()

    def check_sequences(self, session_id: str, sequences: list) -> list[SequenceMatch]:
        if session_id not in self._sessions:
            return []

        actions = list(self._sessions[session_id])
        matches = []

        for seq in sequences:
            result = self._match_sequence(actions, seq)
            if result:
                matches.append(result)

        return matches

    def _match_sequence(
        self,
        actions: list[TrackedAction],
        sequence: dict,
    ) -> SequenceMatch | None:
        pattern = sequence.get("pattern", [])
        if not pattern:
            return None

        step_index = 0
        matched = []

        for action in actions:
            if step_index >= len(pattern):
                break

            step = pattern[step_index]
            if self._action_matches_step(action, step):
                matched.append(action)
                step_index += 1

        if step_index == len(pattern):
            return SequenceMatch(
                sequence_name=sequence.get("name", "unknown"),
                matched_actions=matched,
                severity=Severity(sequence.get("severity", "high")),
            )

        return None

    @staticmethod
    def _action_matches_step(action: TrackedAction, step: dict) -> bool:
        if action.action_type != step.get("action"):
            return False

        condition = step.get("condition", "")
        if not condition:
            return True

        return ActionTracker._check_condition(action, condition)

    @staticmethod
    def _check_condition(action: TrackedAction, condition: str) -> bool:
        if condition == "sensitive":
            return SENSITIVE_PATH_DETECTOR.is_sensitive(action.target)

        if condition == "ssh_related":
            return ".ssh" in action.target.lower() or "ssh" in action.target.lower()

        if condition == "outbound":
            return action.action_type == "http_request" and any(
                m in action.target for m in ("http://", "https://")
            )

        if condition == "network_related":
            network_cmds = ("curl", "wget", "nc", "netcat", "scp", "rsync", "ssh")
            return any(cmd in action.target for cmd in network_cmds)

        if condition == "base64_encode":
            return "base64" in action.target.lower()

        if condition == "cat_sensitive":
            if not action.target.strip().startswith("cat "):
                return False
            target_file = action.target.split("cat ", 1)[-1] if "cat " in action.target else ""
            return SENSITIVE_PATH_DETECTOR.is_sensitive(target_file)

        return True

"""Tests for the correlator module."""

from __future__ import annotations

import time

import pytest

from src.correlator.rules import DEFAULT_SUSPICIOUS_SEQUENCES
from src.correlator.tracker import ActionTracker
from src.policy.models import Severity


@pytest.fixture
def tracker() -> ActionTracker:
    return ActionTracker(window_seconds=30)


class TestActionTracker:
    def test_record_and_retrieve(self, tracker: ActionTracker) -> None:
        tracker.record("session1", "read_file", "/home/user/test.txt")
        assert len(tracker._sessions["session1"]) == 1

    def test_window_pruning(self, tracker: ActionTracker) -> None:
        from collections import deque

        tracker._sessions["session1"] = deque()
        old_action = type(
            "OldAction",
            (),
            {
                "timestamp": time.time() - 60,
                "action_type": "read_file",
                "target": "/tmp/old.txt",
                "metadata": {},
            },
        )()
        tracker._sessions["session1"].append(old_action)
        tracker.record("session1", "read_file", "/tmp/new.txt")
        assert len(tracker._sessions["session1"]) == 1

    def test_sequence_detection(self, tracker: ActionTracker) -> None:
        sequences = [
            {
                "name": "Read secrets then send externally",
                "pattern": [
                    {"action": "read_file", "condition": "sensitive"},
                    {"action": "http_request", "condition": "outbound"},
                ],
                "severity": "critical",
            }
        ]
        tracker.record("session1", "read_file", "~/.ssh/id_rsa")
        tracker.record("session1", "http_request", "https://evil.com/exfil")
        matches = tracker.check_sequences("session1", sequences)
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL

    def test_no_sequence_match(self, tracker: ActionTracker) -> None:
        sequences = [
            {
                "name": "Read secrets then send externally",
                "pattern": [
                    {"action": "read_file", "condition": "sensitive"},
                    {"action": "http_request", "condition": "outbound"},
                ],
                "severity": "critical",
            }
        ]
        tracker.record("session1", "read_file", "/home/user/project/main.py")
        matches = tracker.check_sequences("session1", sequences)
        assert len(matches) == 0

    def test_empty_session(self, tracker: ActionTracker) -> None:
        matches = tracker.check_sequences("nonexistent", [])
        assert len(matches) == 0


class TestDefaultSequences:
    def test_has_sequences(self) -> None:
        assert len(DEFAULT_SUSPICIOUS_SEQUENCES) > 0
        for seq in DEFAULT_SUSPICIOUS_SEQUENCES:
            assert "name" in seq
            assert "pattern" in seq
            assert "severity" in seq

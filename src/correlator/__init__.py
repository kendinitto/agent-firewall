"""Correlator module for Agent Firewall."""

from src.correlator.rules import DEFAULT_SUSPICIOUS_SEQUENCES, get_sequence_for_name
from src.correlator.tracker import ActionTracker, SequenceMatch, TrackedAction

__all__ = [
    "ActionTracker",
    "DEFAULT_SUSPICIOUS_SEQUENCES",
    "SequenceMatch",
    "TrackedAction",
    "get_sequence_for_name",
]

"""Correlation rules for detecting multi-step exfiltration patterns."""

from __future__ import annotations

# Predefined suspicious sequences
DEFAULT_SUSPICIOUS_SEQUENCES = [
    {
        "name": "Read secrets then send externally",
        "pattern": [
            {"action": "read_file", "condition": "sensitive"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
    {
        "name": "Read SSH then curl",
        "pattern": [
            {"action": "read_file", "condition": "ssh_related"},
            {"action": "execute_command", "condition": "network_related"},
        ],
        "severity": "critical",
    },
    {
        "name": "Base64 encode then send",
        "pattern": [
            {"action": "execute_command", "condition": "base64_encode"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
    {
        "name": "Cat sensitive file then network",
        "pattern": [
            {"action": "execute_command", "condition": "cat_sensitive"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
    {
        "name": "Multiple secret reads then upload",
        "pattern": [
            {"action": "read_file", "condition": "sensitive"},
            {"action": "read_file", "condition": "sensitive"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
    {
        "name": "Environment read then external send",
        "pattern": [
            {"action": "execute_command", "condition": "cat_sensitive"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
    {
        "name": "Credential file read then POST",
        "pattern": [
            {"action": "read_file", "condition": "sensitive"},
            {"action": "http_request", "condition": "outbound"},
            {"action": "http_request", "condition": "outbound"},
        ],
        "severity": "critical",
    },
]


def get_sequence_for_name(name: str) -> dict | None:
    for seq in DEFAULT_SUSPICIOUS_SEQUENCES:
        if seq["name"] == name:
            return seq
    return None

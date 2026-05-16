#!/usr/bin/env python3
"""Agent Firewall Hook for opencode.

Drop this into ~/.config/opencode/ and reference it in your opencode config.

This hook intercepts commands before opencode executes them,
checking against the Agent Firewall to block dangerous actions
like reading SSH keys, exfiltrating secrets, etc.

Usage in opencode.json:
{
  "hooks": {
    "pre_command": "~/.config/opencode/firewall_hook.py"
  }
}

The firewall server must be running:
  agent-firewall-start
  # or: python -m src.proxy.server --port 8080

Exit codes:
  0 = allowed (proceed with command)
  126 = blocked (do not execute)
  127 = flagged (warning, but proceed)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error


FIREWALL_URL = os.getenv("FIREWALL_URL", "http://127.0.0.1:8080")
SESSION_ID = os.getenv("FIREWALL_SESSION_ID", "opencode")


def check_command(command: str) -> tuple[int, str]:
    """Check a command against the firewall. Returns (exit_code, message)."""
    payload = json.dumps({
        "action": "execute_command",
        "target": command,
        "session_id": SESSION_ID,
    }).encode()

    try:
        req = urllib.request.Request(
            f"{FIREWALL_URL}/action/check",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status", "allowed")
            reason = data.get("reason", "")

            if status == "blocked":
                return 126, f"[FIREWALL BLOCKED] {reason}"
            elif status == "flagged":
                return 127, f"[FIREWALL WARNING] {reason}"
            return 0, ""
    except urllib.error.HTTPError as e:
        if e.code == 403:
            body = json.loads(e.read().decode())
            reason = body.get("reason", "Blocked")
            return 126, f"[FIREWALL BLOCKED] {reason}"
        return 0, ""  # Allow on server error
    except Exception:
        return 0, ""  # Allow on connection error


def main() -> int:
    if len(sys.argv) < 2:
        return 0

    command = " ".join(sys.argv[1:])
    exit_code, message = check_command(command)

    if message:
        print(message, file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

"""Agent Firewall MCP server.

Runs as a local MCP server (stdio transport) that exposes a firewall-protected
bash tool for opencode to use instead of the built-in bash.

Usage:
    python -m src.proxy.mcp_server
    # or with custom config:
    python -m src.proxy.mcp_server --config /path/to/policy.yaml
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("agent_firewall.mcp")

mcp = FastMCP("Agent Firewall")


def _initialize(config_path: str | Path) -> tuple:
    """Initialize firewall components. Returns (handler, policy_engine)."""
    from src.detection.inspector import ContentInspector
    from src.policy.engine import PolicyEngine
    from src.proxy.handlers import ActionHandler

    if config_path is None:
        config_path = Path("configs/policy.yaml")
    config_path = Path(config_path)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / "configs" / "policy.yaml"

    logger.info("Loading policy from %s", config_path)
    policy = PolicyEngine.from_yaml(str(config_path))
    inspector = ContentInspector(policy)
    handler = ActionHandler(policy, inspector)
    return handler, policy


_handler = None
_policy = None


def get_handler():
    global _handler, _policy
    if _handler is None:
        config = os.getenv("FIREWALL_CONFIG", "")
        _handler, _policy = _initialize(config if config else None)
    return _handler


def execute_command(command: str) -> dict:
    """Execute a shell command after firewall inspection.

    This tool replaces the built-in bash tool. All commands are checked
    against security policies before execution. Blocked commands are
    rejected. Flagged commands execute with a warning.

    Args:
        command: The shell command to execute.

    Returns:
        Dict with stdout, stderr, exit_code, and optional firewall warning.
    """
    from src.detection.inspector import ActionRequest, ActionType

    handler = get_handler()
    inspector = handler._inspector

    request = ActionRequest(
        action=ActionType.EXECUTE_COMMAND,
        target=command,
        session_id="mcp",
    )
    results = inspector.inspect_action(request)

    for result in results:
        if result.is_blocked:
            return {
                "stdout": "",
                "stderr": f"[AGENT FIREWALL] BLOCKED: {result.reason}",
                "exit_code": 126,
            }
        if result.is_flagged:
            warning = f"[AGENT FIREWALL] WARNING: {result.reason}\n"
            break
    else:
        warning = ""

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            env=os.environ.copy(),
        )
        return {
            "stdout": proc.stdout,
            "stderr": warning + proc.stderr,
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": warning + "[TIMEOUT] Command exceeded 300s timeout",
            "exit_code": 124,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": warning + f"[ERROR] {e}",
            "exit_code": 1,
        }


@mcp.tool()
def bash(command: str) -> dict:
    """Execute a shell command (firewall-protected).

    All commands are inspected by the Agent Firewall before execution.
    Dangerous commands (reading SSH keys, exfiltrating secrets, etc.)
    are blocked. Use this instead of any other bash execution tool.

    Args:
        command: The shell command to execute.
    """
    return execute_command(command)


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Firewall MCP Server")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to policy YAML file",
    )
    parser.add_argument("--log-level", default="warning", help="Log level")
    args = parser.parse_args()

    import sys as _sys

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=_sys.stderr,
    )

    global _handler, _policy
    if args.config:
        _handler, _policy = _initialize(args.config)

    logger.info("Starting Agent Firewall MCP server on stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

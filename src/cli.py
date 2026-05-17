"""Agent Firewall CLI.

Usage:
    agent-firewall serve [--port PORT] [--host HOST] [--config PATH]
    agent-firewall mcp [--config PATH] [--log-level LEVEL]
    agent-firewall config
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path


def serve(args: argparse.Namespace) -> None:
    """Start the HTTP proxy server."""

    import uvicorn

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger("agent_firewall")

    logger.info("Starting Agent Firewall on %s:%d", args.host, args.port)
    logger.info("Config: %s", args.config)

    uvicorn.run(
        "src.proxy.server:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )


def config(args: argparse.Namespace) -> None:
    """Print opencode.json config snippet."""

    import json

    config_snippet = {
        "mcp": {
            "firewall": {
                "type": "local",
                "command": ["agent-firewall", "mcp"],
                "enabled": True,
                "timeout": 30000,
            }
        },
        "permission": {
            "bash": "deny",
        },
    }

    print("# Add this to ~/.config/opencode/opencode.json")
    print("#")
    print("# If you installed with a venv, replace 'agent-firewall' with")
    print("# the full path to the binary (e.g., ~/.venv/bin/agent-firewall)")
    print()
    print(json.dumps(config_snippet, indent=2))


def mcp(args: argparse.Namespace) -> None:
    """Start the MCP server (stdio transport)."""

    from mcp.server.fastmcp import FastMCP

    from src.detection.inspector import ActionRequest, ActionType, ContentInspector
    from src.policy.engine import PolicyEngine

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logger = logging.getLogger("agent_firewall.mcp")

    config_path = args.config
    if config_path is None:
        config_path = Path("configs/policy.yaml")
    config_path = Path(config_path)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / "configs" / "policy.yaml"

    logger.info("Loading policy from %s", config_path)
    policy = PolicyEngine.from_yaml(str(config_path))
    inspector = ContentInspector(policy)

    mcp_server = FastMCP("Agent Firewall")

    @mcp_server.tool()
    def bash(command: str) -> dict:
        """Execute a shell command (firewall-protected).

        All commands are inspected by the Agent Firewall before execution.
        Dangerous commands (reading SSH keys, exfiltrating secrets, etc.)
        are blocked. Use this instead of any other bash execution tool.

        Args:
            command: The shell command to execute.
        """

        request = ActionRequest(
            action=ActionType.EXECUTE_COMMAND,
            target=command,
            session_id="mcp",
        )
        results = inspector.inspect_action(request)

        warning = ""
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

    logger.info("Starting Agent Firewall MCP server on stdio")
    mcp_server.run(transport="stdio")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent Firewall - AI agent prompt injection and data exfiltration protection",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Start HTTP proxy server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    serve_parser.add_argument("--config", default="configs/policy.yaml", help="Path to policy YAML")
    serve_parser.add_argument("--log-level", default="info", help="Log level")

    # mcp subcommand
    mcp_parser = subparsers.add_parser("mcp", help="Start MCP server (stdio transport)")
    mcp_parser.add_argument("--config", default=None, help="Path to policy YAML")
    mcp_parser.add_argument("--log-level", default="warning", help="Log level")

    # config subcommand
    subparsers.add_parser("config", help="Print opencode.json config snippet")

    args = parser.parse_args()

    if args.command == "serve":
        serve(args)
    elif args.command == "mcp":
        mcp(args)
    elif args.command == "config":
        config(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

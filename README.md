# Agent Firewall

Protection against AI agent prompt injection and data exfiltration. A framework-agnostic proxy that sits between AI agents and external resources (filesystem, network, tools).

## Installation

```bash
git clone https://github.com/kendinitto/agent-firewall.git
cd agent-firewall
python -m venv .venv
source .venv/bin/activate
pip install .
```

## Usage

### Get Config Snippet

```bash
agent-firewall config
```

Prints the opencode.json snippet to copy-paste.

### MCP Server (for opencode integration)

Start the MCP server:

```bash
agent-firewall mcp
```

### HTTP Proxy Server

```bash
agent-firewall serve --port 8080
```

## Opencode Integration

Add to `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "firewall": {
      "type": "local",
      "command": [
        "agent-firewall",
        "mcp"
      ],
      "enabled": true,
      "timeout": 30000
    }
  },
  "permission": {
    "bash": "deny"
  }
}
```

The `"bash": "deny"` permission forces opencode to use the firewall's `bash` tool from the MCP server instead of the built-in bash.

## How It Works

1. **Fast path** (~microseconds): Precompiled regex patterns against known sensitive paths, domain whitelists/blacklists
2. **Slow path**: Content-aware inspection, sequence correlation when fast path flags something

## Policy Configuration

Default policy is at `configs/policy.yaml`. Override with `--config`:

```bash
agent-firewall mcp --config /path/to/policy.yaml
```

Or set env variable:

```bash
export FIREWALL_CONFIG=/path/to/policy.yaml
```

## Architecture

- **Proxy Layer**: Local HTTP endpoint intercepting agent tool calls
- **Policy Engine**: YAML-configurable rules (sensitive paths, blocked domains, allowed patterns)
- **Action Correlator**: Tracks sequences (e.g., read SSH key -> HTTP POST)
- **Content Inspector**: Detects secrets in data being sent externally
- **Alert System**: Logs blocked actions with optional notifications

## License

MIT

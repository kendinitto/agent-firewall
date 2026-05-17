# Agent Firewall Documentation

## Overview

Agent Firewall protects AI agents from indirect prompt injection attacks that attempt to exfiltrate sensitive files and information through unverified external pathways.

### How It Works

A two-tier processing framework:

1. **Fast path** (~microseconds): Precompiled regex patterns against known sensitive paths, domain whitelists/blacklists. Handles 99% of calls.
2. **Slow path**: Triggered only when fast path flags something. Content-aware inspection, sequence correlation.

### Architecture

```
Agent -> [Agent Firewall MCP] -> External Resources
                    |
              Policy Engine
              Content Inspector
              Action Correlator
```

## Installation

### pip (Recommended)

```bash
pip install agent-firewall
```

### Development

```bash
git clone git@github.com:kendinitto/agent-firewall.git
cd agent-firewall
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI Usage

### MCP Server (opencode integration)

```bash
agent-firewall mcp
```

### HTTP Proxy Server

```bash
agent-firewall serve --port 8080
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Port for HTTP server |
| `--host` | 127.0.0.1 | Host for HTTP server |
| `--config` | configs/policy.yaml | Path to policy YAML |
| `--log-level` | warning | Log level (debug, info, warning, error) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FIREWALL_CONFIG` | Path to policy YAML file |

## Opencode Integration

### 1. Add MCP Server

Add to `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "firewall": {
      "type": "local",
      "command": ["agent-firewall", "mcp"],
      "enabled": true,
      "timeout": 30000
    }
  }
}
```

### 2. Deny Built-in Bash

```json
{
  "permission": {
    "bash": "deny"
  }
}
```

This forces opencode to use the firewall's `bash` tool from the MCP server.

### 3. Auto-Install (Optional)

```bash
bash integrations/opencode/install.sh
```

Merges firewall config into your existing opencode.json.

## Policy Configuration

Full policy reference at `configs/policy.yaml`.

### File Rules

```yaml
files:
  blocked_read_paths:
    - ~/.ssh/
    - ~/.aws/
    - ~/.gnupg/
  blocked_read_patterns:
    - "*.pem"
    - "*.key"
    - "*.env.*"
```

### Network Rules

```yaml
network:
  trusted_domains:
    - github.com
    - pypi.org
  blocked_domains: []
  scrutinize_methods:
    - POST
    - PUT
    - PATCH
  max_fetch_size: 1048576
```

### Command Rules

```yaml
commands:
  blocked_patterns:
    - "curl.*\\|.*bash"
    - "wget.*\\|.*sh"
    - "cat.*\\.ssh"
  approval_required:
    - "chmod"
    - "rm -rf"
    - "sudo"
```

### Content Inspection

```yaml
content_inspection:
  enabled: true
  sensitive_content_patterns:
    - name: "SSH Private Key"
      pattern: "-----BEGIN (RSA |EC |ED25519 )?PRIVATE KEY-----"
      severity: "critical"
    - name: "AWS Access Key"
      pattern: "AKIA[0-9A-Z]{16}"
      severity: "critical"
```

### Action Correlation

```yaml
correlation:
  window_seconds: 30
  suspicious_sequences:
    - name: "Read secrets then send externally"
      pattern:
        - action: "read_file"
          condition: "sensitive"
        - action: "http_request"
          condition: "outbound"
      severity: "critical"
```

## HTTP API

### Endpoints

#### POST /action/check

Check a single action against policies.

**Request:**
```json
{
  "action": "read_file",
  "target": "~/.ssh/id_rsa",
  "session_id": "abc123"
}
```

**Response:**
```json
{
  "status": "blocked",
  "reason": "Sensitive path: ~/.ssh/id_rsa",
  "severity": "critical"
}
```

#### POST /action/batch

Check multiple actions at once.

**Request:**
```json
[
  {
    "action": "read_file",
    "target": "~/project/main.py"
  },
  {
    "action": "http_request",
    "target": "https://github.com/api",
    "method": "GET"
  }
]
```

#### POST /action/passthrough

Proxy a request through the firewall.

#### GET /health

Health check endpoint.

## Detection Patterns

### Sensitive Path Patterns (13)

- SSH keys and config (~/.ssh/*)
- AWS credentials (~/.aws/*)
- GnuPG keys (~/.gnupg/*)
- Environment files (.env*)
- Private keys (*.pem, *.key)
- Credentials files
- System password files (/etc/shadow)

### Injection Patterns (10)

- "Ignore previous instructions"
- "Send secrets to"
- "Read and encode"
- "Output your SSH key"
- Role assignment overrides
- Base64 exfiltration attempts

### Secret Content Patterns (13)

- SSH private/public keys
- AWS access/secret keys
- Generic API tokens
- JWT tokens
- Database connection strings
- GitHub tokens (ghp_, github_pat_)
- npm tokens
- Slack tokens
- Stripe keys
- Passwords in config

## Response Policy

| Detection | Action | Agent Sees | User Sees |
|-----------|--------|------------|-----------|
| Blocked | Hard block | Neutral error | Alert + log |
| Flagged | Allow + warn | Warning in output | Alert + log |
| Clean | Allow | Normal result | Nothing |

## Testing

```bash
pytest tests/ -v          # All tests
ruff check src/ tests/    # Lint
mypy src/                 # Type check
```

## License

MIT

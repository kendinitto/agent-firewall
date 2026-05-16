#!/usr/bin/env bash
# Install Agent Firewall MCP integration for opencode
# Usage: bash integrations/opencode/install.sh

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$HOME/.config/opencode"

echo "=== Agent Firewall - Opencode Integration ==="
echo

# Create config directory
mkdir -p "$CONFIG_DIR"

# Merge config into opencode.json
echo "[1/2] Configuring opencode..."
if [ -f "$CONFIG_DIR/opencode.json" ]; then
    echo "  Merging into existing opencode.json..."
    python3 -c "
import json

# Load existing config
with open('$CONFIG_DIR/opencode.json') as f:
    config = json.load(f)

# Load firewall config
with open('$INSTALL_DIR/opencode.json') as f:
    firewall_config = json.load(f)

# Merge MCP config
if 'mcp' not in config:
    config['mcp'] = {}
config['mcp'].update(firewall_config.get('mcp', {}))

# Merge permissions
if 'permission' not in config:
    config['permission'] = {}
fw_perms = firewall_config.get('permission', {})
for key, value in fw_perms.items():
    config['permission'][key] = value

# Write merged config
with open('$CONFIG_DIR/opencode.json', 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')

print('  Config merged successfully')
"
else
    cp "$INSTALL_DIR/opencode.json" "$CONFIG_DIR/opencode.json"
    echo "  Created: $CONFIG_DIR/opencode.json"
fi

echo "[2/2] Verifying agent-firewall is installed..."
if command -v agent-firewall >/dev/null 2>&1; then
    echo "  agent-firewall found: $(command -v agent-firewall)"
else
    echo "  WARNING: agent-firewall not found in PATH"
    echo "  Install with: pip install agent-firewall"
fi

echo
echo "=== Integration Complete ==="
echo
echo "The firewall runs as an MCP server (no separate process needed)."
echo "opencode will spawn agent-firewall mcp on demand."
echo
echo "To verify setup, run:"
echo "  agent-firewall mcp --help"

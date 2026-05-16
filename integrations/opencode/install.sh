#!/usr/bin/env bash
# Install Agent Firewall integration for opencode
# Usage: bash integrations/opencode/install.sh

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$HOME/.config/opencode"
PROJECT_DIR="$(cd "$INSTALL_DIR/../.." && pwd)"

echo "=== Agent Firewall - Opencode Integration ==="
echo

# Create config directory
mkdir -p "$CONFIG_DIR"

# 1. Install the bash wrapper
echo "[1/3] Installing bash wrapper..."
cp "$INSTALL_DIR/firewall_wrapper.sh" "$CONFIG_DIR/firewall_wrapper.sh"
chmod +x "$CONFIG_DIR/firewall_wrapper.sh"
echo "  Installed: $CONFIG_DIR/firewall_wrapper.sh"

# 2. Merge permission config into opencode.json
echo "[2/3] Configuring opencode permissions..."
if [ -f "$CONFIG_DIR/opencode.json" ]; then
    echo "  Merging into existing opencode.json..."
    python3 -c "
import json, sys

# Load existing config
with open('$CONFIG_DIR/opencode.json') as f:
    config = json.load(f)

# Load firewall permissions
with open('$INSTALL_DIR/opencode.json') as f:
    firewall_config = json.load(f)

# Merge permission rules (firewall rules take precedence for covered keys)
if 'permission' not in config:
    config['permission'] = {}

fw_perms = firewall_config.get('permission', {})
for key, value in fw_perms.items():
    config['permission'][key] = value

# Write merged config
with open('$CONFIG_DIR/opencode.json', 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')

print('  Permissions merged successfully')
"
else
    cp "$INSTALL_DIR/opencode.json" "$CONFIG_DIR/opencode.json"
    echo "  Created: $CONFIG_DIR/opencode.json"
fi

# 3. Create convenience commands
echo "[3/3] Creating convenience commands..."
mkdir -p ~/bin

cat > ~/bin/agent-firewall-start << 'START_EOF'
#!/usr/bin/env bash
cd /home/sixshot/projects/security
nohup .venv/bin/python -m src.proxy.server --port 8080 > ~/.opencode/firewall.log 2>&1 &
echo "Firewall started (PID: $!), logs: ~/.opencode/firewall.log"
START_EOF

cat > ~/bin/agent-firewall-stop << 'STOP_EOF'
#!/usr/bin/env bash
pkill -f "uvicorn.*8080" 2>/dev/null && echo "Firewall stopped" || echo "Not running"
STOP_EOF

cat > ~/bin/agent-firewall-status << 'STATUS_EOF'
#!/usr/bin/env bash
if curl -s http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "Running"
    curl -s http://127.0.0.1:8080/health
else
    echo "Not running"
    exit 1
fi
STATUS_EOF

chmod +x ~/bin/agent-firewall-*
echo "  Commands: agent-firewall-start, agent-firewall-stop, agent-firewall-status"

echo
echo "=== Integration Complete ==="
echo
echo "Two protection layers are now configured:"
echo "  1. Static permission rules in opencode.json (active immediately)"
echo "  2. Dynamic firewall server (start with: agent-firewall-start)"
echo
echo "The opencode.json permission rules will block/ask for dangerous commands"
echo "without needing the firewall server running."
echo
echo "For dynamic detection (sequence correlation, content inspection):"
echo "  agent-firewall-start"
echo

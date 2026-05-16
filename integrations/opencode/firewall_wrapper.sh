#!/usr/bin/env bash
# Agent Firewall bash wrapper for opencode
# Acts as a drop-in replacement for /bin/bash that checks commands against the firewall
#
# Usage: Set shell: "/path/to/firewall_wrapper.sh" in opencode.json
# Or: Run opencode with OPENCODE_SHELL pointing to this wrapper
#
# The firewall server must be running: agent-firewall --port 8080

FIREWALL_URL="${FIREWALL_URL:-http://127.0.0.1:8080}"
FIREWALL_ENABLED="${FIREWALL_ENABLED:-true}"
FIREWALL_MODE="${FIREWALL_MODE:-strict}"

# Actual bash to delegate to
_REAL_BASH="${REAL_BASH:-/bin/bash}"

_firewall_check() {
    local cmd="$1"

    # Skip internal/non-interactive bash invocations
    case "$cmd" in
        -*"c"*) return 0 ;;
    esac

    local resp
    resp=$(curl -s --max-time 3 -w "\n%{http_code}" \
        -X POST "$FIREWALL_URL/action/check" \
        -H "Content-Type: application/json" \
        -d "$(printf '%s' "$cmd" | python3 -c '
import sys, json
print(json.dumps({
    "action": "execute_command",
    "target": sys.stdin.read().strip(),
    "session_id": "opencode-" + str(__import__("os").getpid())
}))
')" 2>/dev/null) || return 0

    local http_code
    http_code=$(echo "$resp" | tail -1)
    local body
    body=$(echo "$resp" | head -n -1)

    if [ "$http_code" = "403" ]; then
        local reason
        reason=$(echo "$body" | python3 -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('reason', 'Blocked by firewall'))
except:
    print('Blocked by firewall')
" 2>/dev/null) || reason="Blocked by firewall"
        echo "[AGENT FIREWALL] BLOCKED: $reason" >&2
        return 126
    fi

    if [ "$http_code" = "200" ]; then
        local status
        status=$(echo "$body" | python3 -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('status', ''))
except:
    print('')
" 2>/dev/null) || status=""

        if [ "$status" = "flagged" ]; then
            local reason
            reason=$(echo "$body" | python3 -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('reason', 'Suspicious activity'))
except:
    print('Suspicious activity')
" 2>/dev/null) || reason="Suspicious activity"
            echo "[AGENT FIREWALL] WARNING: $reason" >&2
        fi
    fi

    return 0
}

# Handle different invocation modes

# Mode 1: Called with -c "command" (typical opencode bash tool usage)
if [ "$1" = "-c" ] && [ -n "$2" ]; then
    if [ "$FIREWALL_ENABLED" = "true" ]; then
        _firewall_check "$2"
        local_exit=$?
        if [ $local_exit -eq 126 ]; then
            exit 126
        fi
        if [ "$FIREWALL_MODE" = "strict" ] && [ $local_exit -ne 0 ]; then
            exit $local_exit
        fi
    fi
    exec "$_REAL_BASH" -c "$2" "$3" "$4"
fi

# Mode 2: Called with script file
if [ -f "$1" ] 2>/dev/null; then
    exec "$_REAL_BASH" "$@"
fi

# Mode 3: Interactive or other flags
exec "$_REAL_BASH" "$@"

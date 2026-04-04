#!/usr/bin/env bash
set -euo pipefail

# deploy_splunkbot_vuln.sh — Deploy vuln_management dashboard + nav + props to splunkbot on AM06

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$REPO_ROOT/.env" ]]; then
    set -a; source "$REPO_ROOT/.env"; set +a
fi

AM06_HOST="${AM06_HOST:-192.168.1.114}"
SSH_USER="${SSH_USER:-dave}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_BIN="${SPLUNK_BIN:-$SPLUNK_HOME/bin/splunk}"

SSH_OPTS="-i $SSH_KEY_PATH -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
SPLUNKBOT_REMOTE="$SPLUNK_HOME/etc/apps/splunkbot"
SPLUNKBOT_LOCAL="$REPO_ROOT/splunk_app/splunkbot"

echo "=== Deploy SplunkBot Vuln Management to AM06 ==="

# Deploy dashboard XML
echo "[1/4] Deploying vuln_management dashboard..."
ssh $SSH_OPTS "$SSH_USER@$AM06_HOST" "mkdir -p $SPLUNKBOT_REMOTE/default/data/ui/views"
scp $SSH_OPTS \
    "$SPLUNKBOT_LOCAL/default/data/ui/views/vuln_management.xml" \
    "$SSH_USER@$AM06_HOST:$SPLUNKBOT_REMOTE/default/data/ui/views/"

# Deploy nav (adds Vuln Management tab)
echo "[2/4] Deploying nav..."
ssh $SSH_OPTS "$SSH_USER@$AM06_HOST" "mkdir -p $SPLUNKBOT_REMOTE/default/data/ui/nav"
scp $SSH_OPTS \
    "$SPLUNKBOT_LOCAL/default/data/ui/nav/default.xml" \
    "$SSH_USER@$AM06_HOST:$SPLUNKBOT_REMOTE/default/data/ui/nav/"

# Deploy props.conf (adds vuln sourcetype parsing)
echo "[3/4] Deploying props.conf..."
scp $SSH_OPTS \
    "$SPLUNKBOT_LOCAL/default/props.conf" \
    "$SSH_USER@$AM06_HOST:$SPLUNKBOT_REMOTE/default/props.conf"

# Restart Splunk
echo "[4/4] Restarting Splunk..."
ssh $SSH_OPTS "$SSH_USER@$AM06_HOST" "$SPLUNK_BIN restart" || echo "WARNING: restart returned non-zero"

echo ""
echo "=== Deploy complete ==="
echo "  Dashboard: http://$AM06_HOST:8000/app/splunkbot/vuln_management"

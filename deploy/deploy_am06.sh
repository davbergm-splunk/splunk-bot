#!/usr/bin/env bash
set -euo pipefail

# SPLUNK-BOT deployment script for AM06
# Deploys the splunk_bot app and its dashboard via REST API

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$REPO_ROOT/splunk_app/splunk_bot"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_USER="${SSH_USER:-dave}"
SSH_HOST="${SSH_HOST:-192.168.1.114}"
SPLUNK_HOME="${SPLUNK_HOME_REMOTE:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"

if [[ -z "$SPLUNK_PASS" ]]; then
    echo "[ERROR] SPLUNK_PASS not set. Export it or source .env"
    exit 1
fi

SSH_CMD="ssh -i $SSH_KEY $SSH_USER@$SSH_HOST"
APP_NAME="splunk_bot"
REMOTE_APP="$SPLUNK_HOME/etc/apps/$APP_NAME"

echo "=== SPLUNK-BOT Deploy to AM06 ==="
echo "[1/5] Syncing app files (excluding dashboards)..."

rsync -avz --delete \
    --exclude='default/data/ui/views/' \
    --exclude='.git' \
    --exclude='__pycache__' \
    -e "ssh -i $SSH_KEY" \
    "$APP_DIR/" \
    "$SSH_USER@$SSH_HOST:$REMOTE_APP/"

echo "[2/5] Ensuring dashboard views directory exists..."
$SSH_CMD "mkdir -p $REMOTE_APP/default/data/ui/views"

echo "[3/5] Creating audit report directory..."
$SSH_CMD "mkdir -p $SPLUNK_HOME/var/log/splunk_bot"

echo "[4/5] Deploying dashboard via REST API..."
DASHBOARD_XML=$(cat "$APP_DIR/default/data/ui/views/bot_audit.xml")

$SSH_CMD "curl -s -k -u '$SPLUNK_USER:$SPLUNK_PASS' \
  'https://127.0.0.1:8089/servicesNS/$SPLUNK_USER/$APP_NAME/data/ui/views/bot_audit' \
  -o /dev/null -w '%{http_code}'" > /tmp/dash_check 2>&1 || true

HTTP_CODE=$(cat /tmp/dash_check | tr -d '[:space:]')

if [[ "$HTTP_CODE" == "200" ]]; then
    echo "  Dashboard exists, updating..."
    $SSH_CMD "curl -s -k -u '$SPLUNK_USER:$SPLUNK_PASS' \
      -X POST 'https://127.0.0.1:8089/servicesNS/$SPLUNK_USER/$APP_NAME/data/ui/views/bot_audit' \
      --data-urlencode 'eai:data@-' <<'XMLEOF'
$DASHBOARD_XML
XMLEOF" > /dev/null
else
    echo "  Dashboard not found, creating..."
    $SSH_CMD "curl -s -k -u '$SPLUNK_USER:$SPLUNK_PASS' \
      -X POST 'https://127.0.0.1:8089/servicesNS/$SPLUNK_USER/$APP_NAME/data/ui/views' \
      -d 'name=bot_audit' \
      --data-urlencode 'eai:data@-' <<'XMLEOF'
$DASHBOARD_XML
XMLEOF" > /dev/null
fi

echo "[5/5] Restarting Splunk..."
$SSH_CMD "$SPLUNK_HOME/bin/splunk restart" || true
sleep 10
$SSH_CMD "$SPLUNK_HOME/bin/splunk status" || $SSH_CMD "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes"

echo ""
echo "=== Verifying dashboard ==="
$SSH_CMD "curl -s -k -u '$SPLUNK_USER:$SPLUNK_PASS' \
  'https://127.0.0.1:8089/servicesNS/$SPLUNK_USER/$APP_NAME/data/ui/views/bot_audit?output_mode=json' \
  | python3 -c \"import sys,json; d=json.load(sys.stdin)['entry'][0]['content']; print('label:', d.get('label'), 'isDashboard:', d.get('isDashboard'), 'version:', d.get('version'))\""

echo ""
echo "=== Deploy complete ==="
echo "Dashboard: http://$SSH_HOST:8000/en-GB/app/$APP_NAME/bot_audit"

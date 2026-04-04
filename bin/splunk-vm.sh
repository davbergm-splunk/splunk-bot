#!/usr/bin/env bash
set -uo pipefail

###############################################################################
# splunk-vm.sh — Start/stop/status/open the SPLUNK-BOT QEMU VM
#
# Commands:
#   start   — Boot the VM (if not already running)
#   stop    — Graceful shutdown via SSH
#   status  — Show VM and Splunk status
#   open    — Auto-login to Splunk Web and open in default browser
#   ssh     — Open an interactive SSH session to the VM
#   restart — Restart Splunk inside the VM
#
# Requires: qemu-system-x86_64, ssh key auth already configured
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Defaults (override with .env) ──────────────────────────────────────────
VM_DIR="${VM_DIR:-$HOME/splunk-vm}"
VM_IMAGE="${VM_IMAGE:-$VM_DIR/splunk-vm.qcow2}"
VM_PIDFILE="${VM_PIDFILE:-$VM_DIR/qemu.pid}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="${SSH_USER:-splunk}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-changeme123}"
SPLUNK_WEB_PORT="${SPLUNK_WEB_PORT:-8000}"
SPLUNK_MGMT_PORT="${SPLUNK_MGMT_PORT:-8089}"

# Load .env if present
[[ -f "$REPO_ROOT/.env" ]] && source "$REPO_ROOT/.env"

# ─── Colors ──────────────────────────────────────────────────────────────────
GRN='\033[0;32m'
YLW='\033[0;33m'
RED='\033[0;31m'
DIM='\033[2m'
BLD='\033[1m'
RST='\033[0m'

SSH_OPTS=(-i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$SSH_PORT")

ssh_vm() {
    ssh "${SSH_OPTS[@]}" "$SSH_USER@localhost" "$@" 2>/dev/null
}

# ─── Commands ────────────────────────────────────────────────────────────────

cmd_status() {
    echo -e "${GRN}> SPLUNK-VM Status${RST}"
    echo ""

    # VM running?
    if [[ -f "$VM_PIDFILE" ]] && kill -0 "$(cat "$VM_PIDFILE")" 2>/dev/null; then
        echo -e "  VM:      ${GRN}${BLD}RUNNING${RST} (PID $(cat "$VM_PIDFILE"))"
    else
        echo -e "  VM:      ${RED}${BLD}STOPPED${RST}"
        return 1
    fi

    # SSH reachable?
    if ssh_vm "echo ok" >/dev/null 2>&1; then
        echo -e "  SSH:     ${GRN}${BLD}OK${RST} (localhost:${SSH_PORT})"
    else
        echo -e "  SSH:     ${RED}${BLD}UNREACHABLE${RST}"
        return 1
    fi

    # Splunk status
    local splunk_status
    splunk_status=$(ssh_vm "ss -tlnp 2>/dev/null | grep -c -E ':8000|:8089'" 2>/dev/null || echo "0")
    if [[ "$splunk_status" -ge 2 ]]; then
        echo -e "  Splunk:  ${GRN}${BLD}UP${RST} (web :${SPLUNK_WEB_PORT} + mgmt :${SPLUNK_MGMT_PORT})"
    elif [[ "$splunk_status" -ge 1 ]]; then
        echo -e "  Splunk:  ${YLW}${BLD}STARTING${RST} (partial — web may still be loading)"
    else
        echo -e "  Splunk:  ${RED}${BLD}DOWN${RST}"
    fi

    echo ""
    echo -e "  ${DIM}Web:  http://127.0.0.1:${SPLUNK_WEB_PORT}${RST}"
    echo -e "  ${DIM}SSH:  ssh -p ${SSH_PORT} ${SSH_USER}@localhost${RST}"
}

cmd_start() {
    if [[ -f "$VM_PIDFILE" ]] && kill -0 "$(cat "$VM_PIDFILE")" 2>/dev/null; then
        echo -e "${YLW}> VM already running (PID $(cat "$VM_PIDFILE"))${RST}"
        return 0
    fi

    if [[ ! -f "$VM_IMAGE" ]]; then
        echo -e "${RED}> VM image not found: ${VM_IMAGE}${RST}"
        echo -e "${DIM}  Create it first with the QEMU setup instructions.${RST}"
        return 1
    fi

    echo -e "${GRN}> Starting SPLUNK-VM...${RST}"
    qemu-system-x86_64 \
        -machine q35 -cpu Haswell-v4 -smp 2 -m 4G \
        -drive file="$VM_IMAGE",format=qcow2,if=virtio \
        -nic user,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${SPLUNK_WEB_PORT}-:8000,hostfwd=tcp::${SPLUNK_MGMT_PORT}-:8089 \
        -nographic -pidfile "$VM_PIDFILE" &
    disown

    echo -e "${DIM}  Waiting for SSH...${RST}"
    for i in $(seq 1 60); do
        sleep 5
        if ssh_vm "echo ok" >/dev/null 2>&1; then
            echo -e "${GRN}> VM is up. SSH ready on localhost:${SSH_PORT}${RST}"
            echo -e "${DIM}  Waiting for Splunk web...${RST}"

            for j in $(seq 1 40); do
                sleep 10
                if ssh_vm "curl -sk -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/" 2>/dev/null | grep -qE "200|303"; then
                    echo -e "${GRN}> Splunk Web ready at http://127.0.0.1:${SPLUNK_WEB_PORT}${RST}"
                    return 0
                fi
            done

            echo -e "${YLW}> Splunk Web not ready yet — try 'splunk-vm.sh status' in a minute${RST}"
            return 0
        fi
    done

    echo -e "${RED}> Timed out waiting for VM SSH${RST}"
    return 1
}

cmd_stop() {
    echo -e "${GRN}> Shutting down SPLUNK-VM...${RST}"
    ssh_vm "sudo shutdown -h now" 2>/dev/null
    sleep 3
    if [[ -f "$VM_PIDFILE" ]]; then
        local pid
        pid=$(cat "$VM_PIDFILE")
        kill "$pid" 2>/dev/null
        rm -f "$VM_PIDFILE"
    fi
    echo -e "${GRN}> VM stopped.${RST}"
}

cmd_ssh() {
    exec ssh "${SSH_OPTS[@]}" "$SSH_USER@localhost"
}

cmd_restart_splunk() {
    echo -e "${GRN}> Restarting Splunk...${RST}"
    ssh_vm "sudo chown -R splunk:splunk /opt/splunk/var/run/splunk/ 2>/dev/null; /opt/splunk/bin/splunk restart 2>&1 | tail -5"
    echo -e "${GRN}> Done.${RST}"
}

cmd_open() {
    local target="${2:-/en-GB/app/splunk_bot/bot_audit}"
    echo -e "${GRN}> Auto-login to Splunk Web...${RST}"

    local session_key
    session_key=$(curl -sk \
        -d "username=${SPLUNK_USER}&password=${SPLUNK_PASS}" \
        "https://127.0.0.1:${SPLUNK_MGMT_PORT}/services/auth/login" \
        2>/dev/null | sed -n 's/.*<sessionKey>\(.*\)<\/sessionKey>.*/\1/p')

    if [[ -z "$session_key" ]]; then
        echo -e "${RED}> Failed to get session token. Is Splunk running?${RST}"
        echo -e "${DIM}  Falling back to login page...${RST}"
        open "http://127.0.0.1:${SPLUNK_WEB_PORT}"
        return 1
    fi

    echo -e "${DIM}  Got session token, setting cookie via redirect...${RST}"

    local redir_port=9876
    python3 -c "
import http.server, threading, time, sys, os

SESSION_KEY = '${session_key}'
TARGET = 'http://127.0.0.1:${SPLUNK_WEB_PORT}${target}'
PORT = ${redir_port}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', TARGET)
        self.send_header('Set-Cookie',
            f'splunkd_${SPLUNK_MGMT_PORT}={SESSION_KEY}; Path=/; HttpOnly')
        self.send_header('Set-Cookie',
            f'token_key={SESSION_KEY}; Path=/')
        self.end_headers()
        threading.Thread(target=lambda: (time.sleep(2), os._exit(0))).start()
    def log_message(self, *a): pass

srv = http.server.HTTPServer(('127.0.0.1', PORT), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.2)
" &
    local py_pid=$!
    sleep 0.5

    open "http://127.0.0.1:${redir_port}/"
    sleep 3
    kill "$py_pid" 2>/dev/null

    echo -e "${GRN}> Opened Splunk Web with auto-login${RST}"
    echo -e "${DIM}  ${target}${RST}"
}

# ─── Main ────────────────────────────────────────────────────────────────────
case "${1:-status}" in
    start)           cmd_start ;;
    stop)            cmd_stop ;;
    status)          cmd_status ;;
    open)            cmd_open "$@" ;;
    ssh)             cmd_ssh ;;
    restart|restart-splunk) cmd_restart_splunk ;;
    *)
        echo "Usage: $0 {start|stop|status|open [/path]|ssh|restart}"
        echo ""
        echo "  start        Boot the QEMU VM"
        echo "  stop         Shutdown the VM"
        echo "  status       Show VM and Splunk status"
        echo "  open [path]  Auto-login and open Splunk Web (default: bot_audit dashboard)"
        echo "  ssh          Open SSH session to VM"
        echo "  restart      Restart Splunk inside VM"
        exit 1
        ;;
esac

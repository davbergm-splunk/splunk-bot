#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# SPLUNK-BOT Audit Runner
#
# Standalone platform health audit for Splunk Enterprise.
# Runs 8 audit domains via SSH, scores findings, and writes JSON events
# to the splunk_bot index for dashboard display.
#
# Usage:
#   ./bin/splunk-bot-audit.sh                    # uses .env
#   ./bin/splunk-bot-audit.sh --host 192.168.1.114 --pass changeme
#   ./bin/splunk-bot-audit.sh --dry-run          # show what would run
#
# Requirements: bash 4+, ssh, jq (optional, for pretty output)
###############################################################################

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Defaults ───────────────────────────────────────────────────────────────
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_USER="${SSH_USER:-dave}"
SSH_HOST="${SSH_HOST:-192.168.1.114}"
SPLUNK_HOME="${SPLUNK_HOME_REMOTE:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"
DRY_RUN=0
REPORT_DIR="${REPO_ROOT}/reports"
AUDIT_LOG_DIR="/opt/splunk/var/log/splunk_bot"

# ─── Color codes ────────────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[0;33m'
CYN='\033[0;36m'
GRN='\033[0;32m'
DIM='\033[2m'
RST='\033[0m'
BLD='\033[1m'

# ─── State ──────────────────────────────────────────────────────────────────
NOW=$(date -u +%Y-%m-%dT%H:%M:%S+0000)
TODAY=$(date +%Y-%m-%d)
AUDIT_ID="$TODAY"
SPLUNK_VER=""
FINDINGS=()
DOMAIN_SCORES=()
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
OK_COUNT=0

# ─── Argument parsing ──────────────────────────────────────────────────────
usage() {
    cat <<USAGE
${BLD}SPLUNK-BOT Audit Runner v${VERSION}${RST}

Usage: $0 [OPTIONS]

Options:
  --host HOST        Splunk host IP/hostname (default: \$SSH_HOST or 192.168.1.114)
  --user USER        SSH user (default: \$SSH_USER or dave)
  --key  PATH        SSH key path (default: \$SSH_KEY or ~/.ssh/id_ed25519)
  --splunk-user USER Splunk admin user (default: \$SPLUNK_USER or admin)
  --splunk-pass PASS Splunk admin password (default: \$SPLUNK_PASS)
  --dry-run          Show commands without executing
  --help             Show this help

Environment:
  Source a .env file or export SSH_HOST, SSH_USER, SSH_KEY,
  SPLUNK_USER, SPLUNK_PASS before running.
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)       SSH_HOST="$2"; shift 2;;
        --user)       SSH_USER="$2"; shift 2;;
        --key)        SSH_KEY="$2"; shift 2;;
        --splunk-user) SPLUNK_USER="$2"; shift 2;;
        --splunk-pass) SPLUNK_PASS="$2"; shift 2;;
        --dry-run)    DRY_RUN=1; shift;;
        --help|-h)    usage;;
        *)            echo "Unknown option: $1"; usage;;
    esac
done

# Source .env if available and password still empty
if [[ -z "$SPLUNK_PASS" && -f "$REPO_ROOT/.env" ]]; then
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.env"
fi

if [[ -z "$SPLUNK_PASS" ]]; then
    echo -e "${RED}[ERROR]${RST} SPLUNK_PASS not set. Use --splunk-pass, export it, or create .env"
    exit 1
fi

# ─── Helpers ────────────────────────────────────────────────────────────────
ssh_cmd() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "${DIM}[DRY-RUN] ssh -i $SSH_KEY $SSH_USER@$SSH_HOST '$1'${RST}" >&2
        echo ""
        return 0
    fi
    ssh -i "$SSH_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$SSH_USER@$SSH_HOST" "$1" 2>/dev/null || echo ""
}

splunk_search() {
    local spl="$1"
    local maxout="${2:-100}"
    ssh_cmd "${SPLUNK_HOME}/bin/splunk search '${spl}' -maxout ${maxout} -auth ${SPLUNK_USER}:${SPLUNK_PASS}"
}

severity_color() {
    case "$1" in
        CRITICAL) echo -e "${RED}";;
        WARNING)  echo -e "${YEL}";;
        INFO)     echo -e "${CYN}";;
        OK)       echo -e "${GRN}";;
        *)        echo -e "${RST}";;
    esac
}

banner() {
    echo ""
    echo -e "${GRN}┌──────────────────────────────────────────────────┐${RST}"
    echo -e "${GRN}│${RST}  ${BLD}> SPLUNK-BOT v${VERSION}${RST}                              ${GRN}│${RST}"
    echo -e "${GRN}│${RST}  ${DIM}Platform Audit Terminal${RST}                          ${GRN}│${RST}"
    echo -e "${GRN}│${RST}                                                  ${GRN}│${RST}"
    echo -e "${GRN}│${RST}  Host: ${BLD}${SSH_HOST}${RST}                           ${GRN}│${RST}"
    echo -e "${GRN}│${RST}  Date: ${BLD}${TODAY}${RST}                              ${GRN}│${RST}"
    echo -e "${GRN}└──────────────────────────────────────────────────┘${RST}"
    echo ""
}

domain_header() {
    local num="$1"
    local name="$2"
    echo ""
    echo -e "${GRN}═══════════════════════════════════════════════════${RST}"
    echo -e "${GRN}  DOMAIN ${num}: ${BLD}${name}${RST}"
    echo -e "${GRN}═══════════════════════════════════════════════════${RST}"
}

record_finding() {
    local domain="$1"
    local domain_label="$2"
    local check="$3"
    local check_label="$4"
    local result="$5"
    local severity="$6"
    local detail="$7"
    local score="$8"

    local color
    color=$(severity_color "$severity")
    echo -e "  ${color}[${severity}]${RST} ${check_label}: ${result}"
    [[ -n "$detail" ]] && echo -e "         ${DIM}${detail}${RST}"

    case "$severity" in
        CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1));;
        WARNING)  WARNING_COUNT=$((WARNING_COUNT + 1));;
        INFO)     INFO_COUNT=$((INFO_COUNT + 1));;
        OK)       OK_COUNT=$((OK_COUNT + 1));;
    esac

    local escaped_result
    escaped_result=$(echo "$result" | sed 's/"/\\"/g')
    local escaped_detail
    escaped_detail=$(echo "$detail" | sed 's/"/\\"/g')

    FINDINGS+=("{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"$(echo "$SSH_HOST" | sed 's/[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/am06/')\",\"splunk_version\":\"${SPLUNK_VER}\",\"event_type\":\"finding\",\"domain\":\"${domain}\",\"domain_label\":\"${domain_label}\",\"check\":\"${check}\",\"check_label\":\"${check_label}\",\"result\":\"${escaped_result}\",\"severity\":\"${severity}\",\"detail\":\"${escaped_detail}\",\"score\":${score}}")
}

record_domain_score() {
    local domain="$1"
    local domain_label="$2"
    local domain_score="$3"
    local domain_weight="$4"
    local weighted
    weighted=$(echo "$domain_score $domain_weight" | awk '{printf "%.1f", $1 * $2 / 100}')

    DOMAIN_SCORES+=("{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"${SPLUNK_VER}\",\"event_type\":\"domain_score\",\"domain\":\"${domain}\",\"domain_label\":\"${domain_label}\",\"domain_score\":${domain_score},\"domain_weight\":${domain_weight},\"weighted_score\":${weighted}}")
}

calc_domain_score() {
    local -a scores=("$@")
    local total=0
    local count=${#scores[@]}
    for s in "${scores[@]}"; do
        total=$((total + s))
    done
    if [[ $count -gt 0 ]]; then
        echo $((total / count))
    else
        echo 0
    fi
}

# ─── Connection test ────────────────────────────────────────────────────────
banner

echo -e "${GRN}> Testing connection...${RST}"
CONN_TEST=$(ssh_cmd "echo SSH_OK && ${SPLUNK_HOME}/bin/splunk version 2>/dev/null || echo SPLUNK_ERROR")

if [[ "$CONN_TEST" != *"SSH_OK"* ]]; then
    echo -e "${RED}[FATAL] Cannot connect to ${SSH_HOST}${RST}"
    exit 1
fi

SPLUNK_VER=$(echo "$CONN_TEST" | sed -n 's/.*Splunk \([0-9.]*\).*/\1/p' | head -1)
SPLUNK_VER=${SPLUNK_VER:-unknown}
echo -e "${GRN}> Connected. Splunk ${SPLUNK_VER}${RST}"

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 1: System Health
# ═══════════════════════════════════════════════════════════════════════════
domain_header 1 "SYSTEM HEALTH"
D1_SCORES=()

# 1.1 Splunk Version
record_finding "system_health" "System Health" "splunk_version" "Splunk Version" \
    "${SPLUNK_VER}" "OK" "" 100
D1_SCORES+=(100)

# 1.2 CPU/RAM
SYS_INFO=$(ssh_cmd "nproc && free -g 2>/dev/null | grep Mem | awk '{print \$2, \$7}' || sysctl -n hw.ncpu 2>/dev/null && echo '? ?'")
CORES=$(echo "$SYS_INFO" | head -1 | tr -d '[:space:]')
MEM_LINE=$(echo "$SYS_INFO" | tail -1)
TOTAL_GB=$(echo "$MEM_LINE" | awk '{print $1}')
AVAIL_GB=$(echo "$MEM_LINE" | awk '{print $2}')

if [[ "$AVAIL_GB" =~ ^[0-9]+$ ]]; then
    if [[ $AVAIL_GB -lt 2 ]]; then
        record_finding "system_health" "System Health" "cpu_ram" "CPU/RAM" \
            "${CORES} cores, ${TOTAL_GB}GB total, ${AVAIL_GB}GB available" "CRITICAL" \
            "Available RAM critically low" 10
        D1_SCORES+=(10)
    elif [[ $AVAIL_GB -lt 4 ]]; then
        record_finding "system_health" "System Health" "cpu_ram" "CPU/RAM" \
            "${CORES} cores, ${TOTAL_GB}GB total, ${AVAIL_GB}GB available" "WARNING" \
            "<4 GB available — monitor for pressure" 45
        D1_SCORES+=(45)
    else
        record_finding "system_health" "System Health" "cpu_ram" "CPU/RAM" \
            "${CORES} cores, ${TOTAL_GB}GB total, ${AVAIL_GB}GB available" "OK" "" 100
        D1_SCORES+=(100)
    fi
else
    record_finding "system_health" "System Health" "cpu_ram" "CPU/RAM" \
        "${CORES} cores (RAM info unavailable)" "INFO" "Could not parse memory info" 70
    D1_SCORES+=(70)
fi

# 1.3 Disk Space
DISK_INFO=$(ssh_cmd "df -h ${SPLUNK_HOME} --output=pcent 2>/dev/null | tail -1 || df -h ${SPLUNK_HOME} | tail -1 | awk '{print \$5}'")
DISK_PCT=$(echo "$DISK_INFO" | tr -d '[:space:]%')

if [[ "$DISK_PCT" =~ ^[0-9]+$ ]]; then
    if [[ $DISK_PCT -gt 95 ]]; then
        record_finding "system_health" "System Health" "disk_space" "Disk Space" \
            "${DISK_PCT}% used" "CRITICAL" "\$SPLUNK_HOME partition critically full" 5
        D1_SCORES+=(5)
    elif [[ $DISK_PCT -gt 85 ]]; then
        record_finding "system_health" "System Health" "disk_space" "Disk Space" \
            "${DISK_PCT}% used" "WARNING" "\$SPLUNK_HOME partition >85% full" 30
        D1_SCORES+=(30)
    elif [[ $DISK_PCT -gt 75 ]]; then
        record_finding "system_health" "System Health" "disk_space" "Disk Space" \
            "${DISK_PCT}% used" "WARNING" "\$SPLUNK_HOME partition >75% full" 40
        D1_SCORES+=(40)
    else
        record_finding "system_health" "System Health" "disk_space" "Disk Space" \
            "${DISK_PCT}% used" "OK" "" 100
        D1_SCORES+=(100)
    fi
else
    record_finding "system_health" "System Health" "disk_space" "Disk Space" \
        "Unable to determine" "INFO" "Could not parse df output" 70
    D1_SCORES+=(70)
fi

# 1.4 Dispatch Dir
DISPATCH_SIZE=$(ssh_cmd "du -sh ${SPLUNK_HOME}/var/run/splunk/dispatch/ 2>/dev/null | awk '{print \$1}'" || echo "N/A")
DISPATCH_NUM=$(echo "$DISPATCH_SIZE" | tr -d '[:alpha:][:space:].')

if [[ "$DISPATCH_SIZE" == *"G"* && "$DISPATCH_NUM" =~ ^[0-9]+ ]]; then
    DISPATCH_GB=${DISPATCH_NUM%%.*}
    if [[ $DISPATCH_GB -gt 50 ]]; then
        record_finding "system_health" "System Health" "dispatch_dir" "Dispatch Dir" \
            "$DISPATCH_SIZE" "CRITICAL" "dispatch >50GB — cleanup urgently needed" 5
        D1_SCORES+=(5)
    elif [[ $DISPATCH_GB -gt 10 ]]; then
        record_finding "system_health" "System Health" "dispatch_dir" "Dispatch Dir" \
            "$DISPATCH_SIZE" "CRITICAL" "dispatch >10GB — cleanup needed" 10
        D1_SCORES+=(10)
    elif [[ $DISPATCH_GB -gt 5 ]]; then
        record_finding "system_health" "System Health" "dispatch_dir" "Dispatch Dir" \
            "$DISPATCH_SIZE" "INFO" "dispatch >5GB" 60
        D1_SCORES+=(60)
    else
        record_finding "system_health" "System Health" "dispatch_dir" "Dispatch Dir" \
            "$DISPATCH_SIZE" "OK" "" 100
        D1_SCORES+=(100)
    fi
else
    record_finding "system_health" "System Health" "dispatch_dir" "Dispatch Dir" \
        "${DISPATCH_SIZE:-N/A}" "OK" "" 90
    D1_SCORES+=(90)
fi

# 1.5 KV Store
KVSTORE=$(ssh_cmd "${SPLUNK_HOME}/bin/splunk show kvstore-status -auth ${SPLUNK_USER}:${SPLUNK_PASS} 2>/dev/null | grep -i 'current status' | head -1" || echo "")
if [[ "$KVSTORE" == *"ready"* ]]; then
    record_finding "system_health" "System Health" "kvstore" "KV Store" \
        "Ready" "OK" "" 100
    D1_SCORES+=(100)
elif [[ "$KVSTORE" == *"down"* || "$KVSTORE" == *"degraded"* ]]; then
    record_finding "system_health" "System Health" "kvstore" "KV Store" \
        "Degraded/Down" "CRITICAL" "KV store not operational" 10
    D1_SCORES+=(10)
else
    record_finding "system_health" "System Health" "kvstore" "KV Store" \
        "${KVSTORE:-Status unknown}" "INFO" "" 70
    D1_SCORES+=(70)
fi

D1_SCORE=$(calc_domain_score "${D1_SCORES[@]}")
record_domain_score "system_health" "System Health" "$D1_SCORE" 15

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 2: Licensing
# ═══════════════════════════════════════════════════════════════════════════
domain_header 2 "LICENSING"
D2_SCORES=()

# 2.1 License type
LIC_TYPE=$(ssh_cmd "${SPLUNK_HOME}/bin/splunk list licenser-licenses -auth ${SPLUNK_USER}:${SPLUNK_PASS} 2>/dev/null | head -10")
if [[ "$LIC_TYPE" == *"enterprise"* || "$LIC_TYPE" == *"Enterprise"* ]]; then
    record_finding "licensing" "Licensing" "license_type" "License Type" \
        "Enterprise" "OK" "" 100
    D2_SCORES+=(100)
elif [[ "$LIC_TYPE" == *"trial"* || "$LIC_TYPE" == *"Trial"* ]]; then
    record_finding "licensing" "Licensing" "license_type" "License Type" \
        "Trial" "WARNING" "Trial license — temporary" 50
    D2_SCORES+=(50)
else
    record_finding "licensing" "Licensing" "license_type" "License Type" \
        "Free/Unknown" "INFO" "" 70
    D2_SCORES+=(70)
fi

# 2.2 Violations
VIOLATIONS=$(splunk_search "index=_internal source=*license_usage.log type=RolloverSummary earliest=-30d | where slaves_usage_bytes>quota | stats count as violations | table violations" 10)
VIO_COUNT=$(echo "$VIOLATIONS" | grep -Eo '[0-9]+' | tail -1 || echo "0")
VIO_COUNT=${VIO_COUNT:-0}

if [[ "$VIO_COUNT" -gt 5 ]]; then
    record_finding "licensing" "Licensing" "violations" "License Violations" \
        "${VIO_COUNT} in 30d" "CRITICAL" "License block imminent" 10
    D2_SCORES+=(10)
elif [[ "$VIO_COUNT" -gt 0 ]]; then
    record_finding "licensing" "Licensing" "violations" "License Violations" \
        "${VIO_COUNT} in 30d" "WARNING" "" 50
    D2_SCORES+=(50)
else
    record_finding "licensing" "Licensing" "violations" "License Violations" \
        "0 in 30d" "OK" "" 100
    D2_SCORES+=(100)
fi

D2_SCORE=$(calc_domain_score "${D2_SCORES[@]}")
record_domain_score "licensing" "Licensing" "$D2_SCORE" 10

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 3: Clustering
# ═══════════════════════════════════════════════════════════════════════════
domain_header 3 "CLUSTERING"
D3_SCORES=()

CLUSTER_CHECK=$(ssh_cmd "${SPLUNK_HOME}/bin/splunk show cluster-config -auth ${SPLUNK_USER}:${SPLUNK_PASS} 2>&1 || echo 'CLUSTERING_DISABLED'")
if [[ "$CLUSTER_CHECK" == *"CLUSTERING_DISABLED"* || "$CLUSTER_CHECK" == *"not enabled"* || "$CLUSTER_CHECK" == *"disabled"* ]]; then
    record_finding "clustering" "Clustering" "cluster_mode" "Cluster Mode" \
        "Standalone (no clustering)" "OK" "Single node — clustering N/A" 100
    D3_SCORES+=(100)
else
    record_finding "clustering" "Clustering" "cluster_mode" "Cluster Mode" \
        "Clustering enabled" "OK" "" 100
    D3_SCORES+=(100)
fi

D3_SCORE=$(calc_domain_score "${D3_SCORES[@]}")
record_domain_score "clustering" "Clustering" "$D3_SCORE" 10

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 4: Apps
# ═══════════════════════════════════════════════════════════════════════════
domain_header 4 "APPS"
D4_SCORES=()

# 4.1 App count
APP_COUNT=$(ssh_cmd "ls ${SPLUNK_HOME}/etc/apps/ | wc -l" | tr -d '[:space:]')
APP_COUNT=${APP_COUNT:-0}

if [[ "$APP_COUNT" -gt 50 ]]; then
    record_finding "apps" "Apps" "app_count" "App Count" \
        "${APP_COUNT} apps installed" "INFO" "High app count — review for unused" 70
    D4_SCORES+=(70)
else
    record_finding "apps" "Apps" "app_count" "App Count" \
        "${APP_COUNT} apps installed" "OK" "" 100
    D4_SCORES+=(100)
fi

# 4.2 btool check
BTOOL_ERRORS=$(ssh_cmd "${SPLUNK_HOME}/bin/splunk btool check --debug 2>&1 | grep -v 'cyber_security\|compliance_essentials\|Splunk_AI_Assistant' | head -20")
BTOOL_COUNT=$(echo "$BTOOL_ERRORS" | grep -c "." 2>/dev/null || echo "0")

if [[ $BTOOL_COUNT -gt 0 && -n "$BTOOL_ERRORS" ]]; then
    record_finding "apps" "Apps" "btool_check" "Config Validation" \
        "${BTOOL_COUNT} warnings" "WARNING" "btool check found config issues" 50
    D4_SCORES+=(50)
else
    record_finding "apps" "Apps" "btool_check" "Config Validation" \
        "Clean" "OK" "" 100
    D4_SCORES+=(100)
fi

D4_SCORE=$(calc_domain_score "${D4_SCORES[@]}")
record_domain_score "apps" "Apps" "$D4_SCORE" 10

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 5: Usage
# ═══════════════════════════════════════════════════════════════════════════
domain_header 5 "USAGE"
D5_SCORES=()

# 5.1 Saved search count
SS_COUNT_RAW=$(splunk_search "| rest /services/saved/searches | search is_scheduled=1 disabled=0 | stats count as total | table total" 10)
SS_COUNT=$(echo "$SS_COUNT_RAW" | grep -Eo '[0-9]+' | tail -1 || echo "0")
SS_COUNT=${SS_COUNT:-0}

if [[ "$SS_COUNT" -gt 100 ]]; then
    record_finding "usage" "Usage" "saved_searches" "Scheduled Searches" \
        "${SS_COUNT} enabled" "WARNING" "High count — scheduling pressure" 40
    D5_SCORES+=(40)
elif [[ "$SS_COUNT" -gt 50 ]]; then
    record_finding "usage" "Usage" "saved_searches" "Scheduled Searches" \
        "${SS_COUNT} enabled" "INFO" "" 65
    D5_SCORES+=(65)
else
    record_finding "usage" "Usage" "saved_searches" "Scheduled Searches" \
        "${SS_COUNT} enabled" "OK" "" 100
    D5_SCORES+=(100)
fi

D5_SCORE=$(calc_domain_score "${D5_SCORES[@]}")
record_domain_score "usage" "Usage" "$D5_SCORE" 10

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 6: Search Performance
# ═══════════════════════════════════════════════════════════════════════════
domain_header 6 "SEARCH PERFORMANCE"
D6_SCORES=()

# 6.1 Long-running searches
LONG_SEARCHES=$(splunk_search "index=_audit action=search info=completed earliest=-7d | where total_run_time>600 | stats count as long_count | table long_count" 10)
LONG_COUNT=$(echo "$LONG_SEARCHES" | grep -Eo '[0-9]+' | tail -1 || echo "0")
LONG_COUNT=${LONG_COUNT:-0}

if [[ "$LONG_COUNT" -gt 10 ]]; then
    record_finding "search" "Search Perf" "long_running" "Long Running Searches" \
        "${LONG_COUNT} searches >600s" "CRITICAL" "Excessive long-running searches" 15
    D6_SCORES+=(15)
elif [[ "$LONG_COUNT" -gt 0 ]]; then
    record_finding "search" "Search Perf" "long_running" "Long Running Searches" \
        "${LONG_COUNT} searches >600s" "WARNING" "" 40
    D6_SCORES+=(40)
else
    record_finding "search" "Search Perf" "long_running" "Long Running Searches" \
        "None >600s" "OK" "" 100
    D6_SCORES+=(100)
fi

# 6.2 Real-time searches
RT_SEARCHES=$(splunk_search "| rest /services/search/jobs | search isRealTimeSearch=1 | stats count as rt_count | table rt_count" 10)
RT_COUNT=$(echo "$RT_SEARCHES" | grep -Eo '[0-9]+' | tail -1 || echo "0")
RT_COUNT=${RT_COUNT:-0}

if [[ "$RT_COUNT" -gt 10 ]]; then
    record_finding "search" "Search Perf" "realtime" "Real-Time Searches" \
        "${RT_COUNT} active" "CRITICAL" "Excessive RT searches" 15
    D6_SCORES+=(15)
elif [[ "$RT_COUNT" -gt 3 ]]; then
    record_finding "search" "Search Perf" "realtime" "Real-Time Searches" \
        "${RT_COUNT} active" "WARNING" "" 45
    D6_SCORES+=(45)
elif [[ "$RT_COUNT" -gt 0 ]]; then
    record_finding "search" "Search Perf" "realtime" "Real-Time Searches" \
        "${RT_COUNT} active" "INFO" "" 70
    D6_SCORES+=(70)
else
    record_finding "search" "Search Perf" "realtime" "Real-Time Searches" \
        "0 active" "OK" "" 100
    D6_SCORES+=(100)
fi

# 6.3 Search concurrency
ACTIVE_JOBS=$(splunk_search "| rest /services/search/jobs | stats count as active | table active" 10)
ACTIVE_COUNT=$(echo "$ACTIVE_JOBS" | grep -Eo '[0-9]+' | tail -1 || echo "0")
ACTIVE_COUNT=${ACTIVE_COUNT:-0}
MAX_SEARCHES=$((${CORES:-4} * 2 + 6))

if [[ $ACTIVE_COUNT -gt $((MAX_SEARCHES * 90 / 100)) ]]; then
    record_finding "search" "Search Perf" "concurrency" "Search Concurrency" \
        "Peak ${ACTIVE_COUNT} of ${MAX_SEARCHES} limit" "CRITICAL" ">90% of max" 15
    D6_SCORES+=(15)
elif [[ $ACTIVE_COUNT -gt $((MAX_SEARCHES * 70 / 100)) ]]; then
    record_finding "search" "Search Perf" "concurrency" "Search Concurrency" \
        "Peak ${ACTIVE_COUNT} of ${MAX_SEARCHES} limit" "WARNING" ">70% of max — risk of queuing" 40
    D6_SCORES+=(40)
else
    record_finding "search" "Search Perf" "concurrency" "Search Concurrency" \
        "${ACTIVE_COUNT} of ${MAX_SEARCHES} limit" "OK" "" 100
    D6_SCORES+=(100)
fi

D6_SCORE=$(calc_domain_score "${D6_SCORES[@]}")
record_domain_score "search" "Search Perf" "$D6_SCORE" 20

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 7: Dashboards
# ═══════════════════════════════════════════════════════════════════════════
domain_header 7 "DASHBOARDS"
D7_SCORES=()

# 7.1 Dashboard count and Studio v2 ratio
DASH_COUNT_RAW=$(splunk_search "| rest /servicesNS/-/-/data/ui/views | search isDashboard=1 | eval type=if(like(eai:data, \\\"%version=\\\\\\\"2\\\\\\\"%\\\"), \\\"studio_v2\\\", \\\"classic_xml\\\") | stats count by type | table type count" 20)
STUDIO_COUNT=$(echo "$DASH_COUNT_RAW" | grep -i "studio" | grep -Eo '[0-9]+' | tail -1 || echo "0")
CLASSIC_COUNT=$(echo "$DASH_COUNT_RAW" | grep -i "classic" | grep -Eo '[0-9]+' | tail -1 || echo "0")
TOTAL_DASH=$((${STUDIO_COUNT:-0} + ${CLASSIC_COUNT:-0}))

record_finding "dashboards" "Dashboards" "studio_ratio" "Studio v2 Ratio" \
    "${STUDIO_COUNT:-0}/${TOTAL_DASH} Studio v2" "OK" "" 100
D7_SCORES+=(100)

D7_SCORE=$(calc_domain_score "${D7_SCORES[@]}")
record_domain_score "dashboards" "Dashboards" "$D7_SCORE" 10

# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 8: Indexes
# ═══════════════════════════════════════════════════════════════════════════
domain_header 8 "INDEXES"
D8_SCORES=()

# 8.1 Index count and total size
INDEX_INFO=$(splunk_search "| rest /services/data/indexes | search totalEventCount>0 | stats count as idx_count sum(currentDBSizeMB) as total_mb | eval total_gb=round(total_mb/1024,1) | table idx_count total_gb" 10)
IDX_COUNT=$(echo "$INDEX_INFO" | grep -Eo '[0-9]+' | head -1 || echo "0")
TOTAL_GB_IDX=$(echo "$INDEX_INFO" | grep -Eo '[0-9.]+' | tail -1 || echo "0")

record_finding "indexes" "Indexes" "total_size" "Total Index Size" \
    "${TOTAL_GB_IDX:-0} GB across ${IDX_COUNT:-0} indexes" "OK" "" 100
D8_SCORES+=(100)

# 8.2 Dead indexes
DEAD_IDX=$(splunk_search "| rest /services/data/indexes | search disabled=0 totalEventCount=0 | stats count as dead | table dead" 10)
DEAD_COUNT=$(echo "$DEAD_IDX" | grep -Eo '[0-9]+' | tail -1 || echo "0")
DEAD_COUNT=${DEAD_COUNT:-0}

if [[ "$DEAD_COUNT" -gt 0 ]]; then
    record_finding "indexes" "Indexes" "dead_indexes" "Dead Indexes" \
        "${DEAD_COUNT} empty indexes" "INFO" "Candidates for removal" 70
    D8_SCORES+=(70)
else
    record_finding "indexes" "Indexes" "dead_indexes" "Dead Indexes" \
        "0 dead indexes" "OK" "" 100
    D8_SCORES+=(100)
fi

D8_SCORE=$(calc_domain_score "${D8_SCORES[@]}")
record_domain_score "indexes" "Indexes" "$D8_SCORE" 15

# ═══════════════════════════════════════════════════════════════════════════
# SCORING & OUTPUT
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GRN}═══════════════════════════════════════════════════${RST}"
echo -e "${GRN}  ${BLD}AUDIT COMPLETE${RST}"
echo -e "${GRN}═══════════════════════════════════════════════════${RST}"

TOTAL_FINDINGS=$((CRITICAL_COUNT + WARNING_COUNT + INFO_COUNT + OK_COUNT))

if [[ $CRITICAL_COUNT -gt 0 ]]; then
    OVERALL_STATUS="CRITICAL"
    STATUS_COLOR="$RED"
elif [[ $WARNING_COUNT -gt 0 ]]; then
    OVERALL_STATUS="WARNING"
    STATUS_COLOR="$YEL"
else
    OVERALL_STATUS="HEALTHY"
    STATUS_COLOR="$GRN"
fi

# Weighted overall score from domain scores
OVERALL_SCORE=0
for ds in "${DOMAIN_SCORES[@]}"; do
    WS=$(echo "$ds" | sed -n 's/.*"weighted_score":\([0-9.]*\).*/\1/p' || echo "0")
    WS=${WS:-0}
    WS_INT=$(echo "$WS" | awk '{printf "%d", $1}')
    OVERALL_SCORE=$((OVERALL_SCORE + WS_INT))
done

echo ""
echo -e "  ${BLD}Health Score:${RST}  ${STATUS_COLOR}${BLD}${OVERALL_SCORE} / 100${RST}"
echo -e "  ${BLD}Status:${RST}        ${STATUS_COLOR}${BLD}${OVERALL_STATUS}${RST}"
echo -e "  ${BLD}Findings:${RST}      ${TOTAL_FINDINGS} total"
echo -e "    ${RED}CRITICAL:${RST} ${CRITICAL_COUNT}  ${YEL}WARNING:${RST} ${WARNING_COUNT}  ${CYN}INFO:${RST} ${INFO_COUNT}  ${GRN}OK:${RST} ${OK_COUNT}"
echo ""

# ─── Write JSON events to Splunk ────────────────────────────────────────────
SUMMARY_JSON="{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"${SPLUNK_VER}\",\"event_type\":\"summary\",\"overall_score\":${OVERALL_SCORE},\"overall_status\":\"${OVERALL_STATUS}\",\"critical_count\":${CRITICAL_COUNT},\"warning_count\":${WARNING_COUNT},\"info_count\":${INFO_COUNT},\"ok_count\":${OK_COUNT},\"domains_audited\":8}"

ALL_EVENTS="$SUMMARY_JSON"
for ds in "${DOMAIN_SCORES[@]}"; do
    ALL_EVENTS="${ALL_EVENTS}\n${ds}"
done
for f in "${FINDINGS[@]}"; do
    ALL_EVENTS="${ALL_EVENTS}\n${f}"
done

if [[ $DRY_RUN -eq 0 ]]; then
    echo -e "${GRN}> Writing events to Splunk index...${RST}"
    echo -e "$ALL_EVENTS" | ssh -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "mkdir -p ${AUDIT_LOG_DIR} && cat > ${AUDIT_LOG_DIR}/audit_${TODAY}.json"
    echo -e "${GRN}> Done. Events written to ${AUDIT_LOG_DIR}/audit_${TODAY}.json${RST}"
else
    echo -e "${DIM}[DRY-RUN] Would write ${TOTAL_FINDINGS} findings + 8 domain scores + 1 summary${RST}"
fi

# ─── Write local markdown report ────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
REPORT_FILE="${REPORT_DIR}/SPLUNK_BOT_AUDIT_${TODAY}.md"

cat > "$REPORT_FILE" << MDEOF
# SPLUNK-BOT Audit Report

**Host**: ${SSH_HOST}
**Splunk Version**: ${SPLUNK_VER}
**Audit Date**: ${TODAY}
**Overall Health**: ${OVERALL_STATUS}
**Health Score**: ${OVERALL_SCORE} / 100

## Summary

${TOTAL_FINDINGS} findings across 8 domains:
- ${CRITICAL_COUNT} Critical
- ${WARNING_COUNT} Warning
- ${INFO_COUNT} Info
- ${OK_COUNT} OK

## Findings

$(for f in "${FINDINGS[@]}"; do
    SEV=$(echo "$f" | sed -n 's/.*"severity":"\([^"]*\).*/\1/p')
    CHK=$(echo "$f" | sed -n 's/.*"check_label":"\([^"]*\).*/\1/p')
    RES=$(echo "$f" | sed -n 's/.*"result":"\([^"]*\).*/\1/p')
    DTL=$(echo "$f" | sed -n 's/.*"detail":"\([^"]*\).*/\1/p')
    echo "| ${SEV} | ${CHK} | ${RES} | ${DTL} |"
done)

---
*Generated by SPLUNK-BOT v${VERSION}*
MDEOF

echo -e "${GRN}> Report saved: ${REPORT_FILE}${RST}"
echo ""
echo -e "${GRN}> Dashboard: http://${SSH_HOST}:8000/en-GB/app/splunk_bot/bot_audit${RST}"
echo ""

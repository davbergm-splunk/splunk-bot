"""
SPLUNK-BOT Audit Runner — runs inside Splunk as a scripted input.

Performs 8 domain health checks using Splunk REST endpoints and local
OS commands, scores findings, and writes JSON events to the splunk_bot
index via file output to $SPLUNK_HOME/var/log/splunk_bot/.

Designed for Splunk embedded Python 3.9+ (no external dependencies).
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
import urllib.parse
import ssl
from datetime import datetime, timezone

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
SESSION_KEY = None
SPLUNK_HOST = "127.0.0.1"
SPLUNK_MGMT_PORT = "8089"
AUDIT_LOG_DIR = os.path.join(SPLUNK_HOME, "var", "log", "splunk_bot")

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
AUDIT_ID = TODAY

FINDINGS = []
DOMAIN_SCORES = []
CRITICAL_COUNT = 0
WARNING_COUNT = 0
INFO_COUNT = 0
OK_COUNT = 0
SPLUNK_VER = "unknown"
HOSTNAME = "splunk"


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_session_key():
    """Read session key from stdin (Splunk passes it for scripted inputs)."""
    global SESSION_KEY
    if SESSION_KEY:
        return SESSION_KEY

    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        for line in raw.splitlines():
            if line.startswith("sessionKey="):
                SESSION_KEY = line.split("=", 1)[1]
                return SESSION_KEY
            stripped = line.strip()
            if stripped and not stripped.startswith("<"):
                SESSION_KEY = stripped
                return SESSION_KEY

    splunk_user = os.environ.get("SPLUNK_USER", "admin")
    splunk_pass = os.environ.get("SPLUNK_PASS", "")
    if splunk_pass:
        SESSION_KEY = auth_with_password(splunk_user, splunk_pass)
        return SESSION_KEY

    return None


def auth_with_password(user, password):
    """Authenticate to Splunk and get a session key."""
    url = "https://{}:{}/services/auth/login".format(SPLUNK_HOST, SPLUNK_MGMT_PORT)
    data = urllib.parse.urlencode({
        "username": user,
        "password": password,
        "output_mode": "json",
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    resp = urllib.request.urlopen(req, context=_ssl_ctx())
    body = json.loads(resp.read().decode("utf-8"))
    return body.get("sessionKey", "")


def splunk_rest(endpoint, params=None):
    """Call Splunk REST API (GET) and return parsed JSON."""
    url = "https://{}:{}{}".format(SPLUNK_HOST, SPLUNK_MGMT_PORT, endpoint)
    if params:
        url += "?" + urllib.parse.urlencode(params)

    key = get_session_key()
    if not key:
        return {}

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Splunk {}".format(key))

    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx())
        return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.stderr.write("REST {} -> HTTP {}\n".format(endpoint, e.code))
        return {}
    except Exception as e:
        sys.stderr.write("REST {} -> {}\n".format(endpoint, e))
        return {}


def splunk_search_oneshot(spl, max_count=100):
    """Run a oneshot search and return results."""
    url = "https://{}:{}/services/search/jobs/oneshot".format(
        SPLUNK_HOST, SPLUNK_MGMT_PORT
    )

    key = get_session_key()
    if not key:
        return []

    data = urllib.parse.urlencode({
        "search": spl,
        "output_mode": "json",
        "count": max_count,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", "Splunk {}".format(key))

    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx())
        body = json.loads(resp.read().decode("utf-8"))
        return body.get("results", [])
    except Exception as e:
        sys.stderr.write("ONESHOT error: {}\n".format(e))
        return []


def run_cmd(cmd):
    """Run a local shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _hostname():
    global HOSTNAME
    if HOSTNAME == "splunk":
        h = run_cmd("hostname")
        HOSTNAME = h.split(".")[0] if h else "splunk"
    return HOSTNAME


def record_finding(domain, domain_label, check, check_label, result,
                   severity, detail, score, fix_prompt=""):
    """Record an audit finding."""
    global CRITICAL_COUNT, WARNING_COUNT, INFO_COUNT, OK_COUNT

    if severity == "CRITICAL":
        CRITICAL_COUNT += 1
    elif severity == "WARNING":
        WARNING_COUNT += 1
    elif severity == "INFO":
        INFO_COUNT += 1
    elif severity == "OK":
        OK_COUNT += 1

    finding = {
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": _hostname(),
        "splunk_version": SPLUNK_VER,
        "event_type": "finding",
        "domain": domain,
        "domain_label": domain_label,
        "check": check,
        "check_label": check_label,
        "result": str(result),
        "severity": severity,
        "detail": detail,
        "score": score,
    }
    if fix_prompt:
        finding["fix_prompt"] = fix_prompt
    FINDINGS.append(finding)


def record_domain_score(domain, domain_label, domain_score, weight):
    """Record a domain score."""
    weighted = round(domain_score * weight / 100.0, 1)
    DOMAIN_SCORES.append({
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": _hostname(),
        "splunk_version": SPLUNK_VER,
        "event_type": "domain_score",
        "domain": domain,
        "domain_label": domain_label,
        "domain_score": domain_score,
        "domain_weight": weight,
        "weighted_score": weighted,
    })


def calc_domain_score(scores):
    """Average a list of integer scores."""
    if not scores:
        return 0
    return sum(scores) // len(scores)


def safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def safe_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 1: System Health
# ═══════════════════════════════════════════════════════════════════════════

def audit_system_health():
    global SPLUNK_VER
    scores = []

    # 1.1 Splunk version
    ver_info = splunk_rest("/services/server/info", {"output_mode": "json"})
    entries = ver_info.get("entry", [])
    if entries:
        content = entries[0].get("content", {})
        SPLUNK_VER = content.get("version", "unknown")
        build = content.get("build", "")
        os_name = content.get("os_name", "")
        record_finding("system_health", "System Health", "splunk_version",
                       "Splunk Version",
                       "{} build {} ({})".format(SPLUNK_VER, build, os_name),
                       "OK", "", 100)
        scores.append(100)
    else:
        record_finding("system_health", "System Health", "splunk_version",
                       "Splunk Version", "unknown", "WARNING",
                       "REST /services/server/info returned empty — check permissions",
                       50,
                       fix_prompt="Investigate why /services/server/info returns empty. "
                       "Check that the audit script's session key has admin access. "
                       "Run: curl -k -u admin:pass https://localhost:8089/services/server/info?output_mode=json")
        scores.append(50)

    # 1.2 CPU / RAM
    cores = run_cmd("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 0")
    mem_raw = run_cmd("free -g 2>/dev/null | grep Mem || echo ''")
    if mem_raw:
        parts = mem_raw.split()
        total_gb = parts[1] if len(parts) > 1 else "?"
        avail_gb = parts[6] if len(parts) > 6 else parts[-1] if len(parts) > 1 else "?"
        avail_int = safe_int(avail_gb, -1)
        if avail_int >= 0:
            if avail_int < 2:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM",
                               "{} cores, {}GB total, {}GB avail".format(cores, total_gb, avail_gb),
                               "CRITICAL", "Available RAM critically low", 10,
                               fix_prompt="Available RAM is under 2GB. Identify and stop memory-hungry "
                               "processes or add more RAM. Check: ps aux --sort=-%mem | head -10")
                scores.append(10)
            elif avail_int < 4:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM",
                               "{} cores, {}GB total, {}GB avail".format(cores, total_gb, avail_gb),
                               "WARNING", "<4 GB available — monitor for pressure", 45,
                               fix_prompt="Available RAM is under 4GB. Review Splunk memory usage and "
                               "consider increasing server RAM or reducing concurrent search load.")
                scores.append(45)
            else:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM",
                               "{} cores, {}GB total, {}GB avail".format(cores, total_gb, avail_gb),
                               "OK", "", 100)
                scores.append(100)
        else:
            record_finding("system_health", "System Health", "cpu_ram",
                           "CPU/RAM", "{} cores (RAM parse failed)".format(cores),
                           "INFO", "Could not parse memory info", 70,
                           fix_prompt="Could not parse 'free -g' output. Check that the command "
                           "is available on this host and returns expected format.")
            scores.append(70)
    else:
        record_finding("system_health", "System Health", "cpu_ram",
                       "CPU/RAM", "{} cores (RAM N/A)".format(cores),
                       "INFO", "No free command — might be container or macOS", 70,
                       fix_prompt="The 'free' command is not available. If running in a container, "
                       "check /proc/meminfo directly or use 'cat /proc/meminfo | grep MemAvailable'.")
        scores.append(70)

    # 1.3 Disk space
    disk_raw = run_cmd("df -h {} 2>/dev/null | tail -1".format(SPLUNK_HOME))
    disk_pct = 0
    if disk_raw:
        match = re.search(r"(\d+)%", disk_raw)
        if match:
            disk_pct = int(match.group(1))
    if disk_pct > 95:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "CRITICAL", "$SPLUNK_HOME partition critically full", 5,
                       fix_prompt="Disk is {}% full. Immediately free space: clean frozen buckets, "
                       "purge old dispatch dirs, remove unused indexes. "
                       "Run: du -sh {}/* | sort -rh | head -10".format(disk_pct, SPLUNK_HOME))
        scores.append(5)
    elif disk_pct > 85:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "WARNING", "$SPLUNK_HOME >85% full", 30,
                       fix_prompt="Disk is {}% full. Review index retention policies and clean "
                       "dispatch directory. Consider adding storage or archiving cold data.".format(disk_pct))
        scores.append(30)
    elif disk_pct > 75:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "WARNING", "$SPLUNK_HOME >75% full", 40,
                       fix_prompt="Disk is {}% full. Plan capacity — review index sizes and "
                       "retention. Set up monitoring alerts for 85% threshold.".format(disk_pct))
        scores.append(40)
    elif disk_pct > 0:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct), "OK", "", 100)
        scores.append(100)
    else:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "Unable to determine", "INFO",
                       "Could not parse df output", 70,
                       fix_prompt="df command did not return expected output for {}. "
                       "Check filesystem mounts manually.".format(SPLUNK_HOME))
        scores.append(70)

    # 1.4 Dispatch directory
    dispatch_dir = os.path.join(SPLUNK_HOME, "var", "run", "splunk", "dispatch")
    dispatch_raw = run_cmd("du -sh {} 2>/dev/null".format(dispatch_dir))
    dispatch_size = dispatch_raw.split()[0] if dispatch_raw else "N/A"
    if "G" in dispatch_size:
        num = re.search(r"([\d.]+)", dispatch_size)
        if num:
            gb = float(num.group(1))
            if gb > 50:
                record_finding("system_health", "System Health", "dispatch_dir",
                               "Dispatch Dir", dispatch_size,
                               "CRITICAL", "dispatch >50GB — urgent cleanup", 5,
                               fix_prompt="Dispatch directory is {}. Purge stale search artifacts: "
                               "$SPLUNK_HOME/bin/splunk clean-dispatch -f".format(dispatch_size))
                scores.append(5)
            elif gb > 10:
                record_finding("system_health", "System Health", "dispatch_dir",
                               "Dispatch Dir", dispatch_size,
                               "WARNING", "dispatch >10GB — cleanup needed", 30,
                               fix_prompt="Dispatch directory is {}. Review long-running saved searches "
                               "with dispatch.ttl settings. Clean old artifacts.".format(dispatch_size))
                scores.append(30)
            elif gb > 5:
                record_finding("system_health", "System Health", "dispatch_dir",
                               "Dispatch Dir", dispatch_size,
                               "INFO", "dispatch >5GB", 60)
                scores.append(60)
            else:
                record_finding("system_health", "System Health", "dispatch_dir",
                               "Dispatch Dir", dispatch_size, "OK", "", 100)
                scores.append(100)
        else:
            record_finding("system_health", "System Health", "dispatch_dir",
                           "Dispatch Dir", dispatch_size, "OK", "", 90)
            scores.append(90)
    else:
        record_finding("system_health", "System Health", "dispatch_dir",
                       "Dispatch Dir", dispatch_size, "OK", "", 90)
        scores.append(90)

    # 1.5 KV Store
    kv_data = splunk_rest("/services/kvstore/status", {"output_mode": "json"})
    kv_entries = kv_data.get("entry", [])
    kv_status = "unknown"
    if kv_entries:
        current = kv_entries[0].get("content", {}).get("current", {})
        if isinstance(current, dict):
            kv_status = current.get("status", "unknown")
        else:
            kv_status = str(kv_entries[0].get("content", {}).get("status", "unknown"))
    if kv_status == "ready":
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", "Ready", "OK", "", 100)
        scores.append(100)
    elif kv_status in ("down", "degraded"):
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", kv_status.title(),
                       "CRITICAL", "KV store not operational", 10,
                       fix_prompt="KV Store is {}. Restart KV store: "
                       "$SPLUNK_HOME/bin/splunk restart splunkd. "
                       "Check mongod logs in $SPLUNK_HOME/var/log/splunk/mongod.log".format(kv_status))
        scores.append(10)
    else:
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", kv_status, "INFO",
                       "Could not determine KV store status", 70,
                       fix_prompt="KV store status is '{}'. Verify with: "
                       "$SPLUNK_HOME/bin/splunk show kvstore-status".format(kv_status))
        scores.append(70)

    score = calc_domain_score(scores)
    record_domain_score("system_health", "System Health", score, 15)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 2: Licensing
# ═══════════════════════════════════════════════════════════════════════════

def audit_licensing():
    scores = []

    # 2.1 License type
    lic_data = splunk_rest("/services/licenser/licenses", {"output_mode": "json"})
    lic_entries = lic_data.get("entry", [])
    lic_type = "unknown"
    for entry in lic_entries:
        t = entry.get("content", {}).get("type", "")
        if t == "enterprise":
            lic_type = "Enterprise"
            break
        elif t == "trial":
            lic_type = "Trial"
        elif t == "free":
            lic_type = "Free"

    if lic_type == "Enterprise":
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Enterprise", "OK", "", 100)
        scores.append(100)
    elif lic_type == "Trial":
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Trial", "WARNING",
                       "Trial license — temporary", 50,
                       fix_prompt="Splunk is running a Trial license which expires. "
                       "Apply an Enterprise or Developer license via: "
                       "Settings > Licensing > Add License")
        scores.append(50)
    elif lic_type == "Free":
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Free", "INFO",
                       "Free license — limited to 500MB/day, no auth", 60,
                       fix_prompt="Running on Free license (500MB/day, no authentication). "
                       "Consider upgrading to Enterprise or Developer license for "
                       "auth, alerting, and higher ingest limits.")
        scores.append(60)
    else:
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Unknown", "INFO",
                       "Could not determine license type", 70,
                       fix_prompt="License type could not be determined. Check: "
                       "$SPLUNK_HOME/bin/splunk list licenser-licenses")
        scores.append(70)

    # 2.2 License usage vs quota
    usage_results = splunk_search_oneshot(
        'search index=_internal source=*license_usage.log type=Usage earliest=-1d '
        '| stats sum(b) as bytes_used | eval gb=round(bytes_used/1024/1024/1024,2) '
        '| table gb'
    )
    quota_data = splunk_rest("/services/licenser/pools", {"output_mode": "json"})
    quota_gb = 0
    for entry in quota_data.get("entry", []):
        qb = safe_float(entry.get("content", {}).get("effective_quota", 0))
        if qb > 0:
            quota_gb = round(qb / 1024 / 1024 / 1024, 1)
            break

    usage_gb = 0
    if usage_results:
        usage_gb = safe_float(usage_results[0].get("gb", 0))

    if quota_gb > 0:
        pct = round(usage_gb / quota_gb * 100, 1) if quota_gb else 0
        record_finding("licensing", "Licensing", "daily_usage",
                       "Daily Usage",
                       "{} GB/day ({} GB quota, {}%)".format(usage_gb, quota_gb, pct),
                       "OK" if pct < 80 else ("WARNING" if pct < 95 else "CRITICAL"),
                       "" if pct < 80 else "License usage at {}% of quota".format(pct),
                       100 if pct < 80 else (40 if pct < 95 else 10),
                       fix_prompt="" if pct < 80 else
                       "License usage is at {}% of the {} GB quota. Reduce ingestion volume "
                       "or increase license capacity. Check top sources: "
                       "index=_internal source=*license_usage.log type=Usage | stats sum(b) by s | sort -sum(b)".format(pct, quota_gb))
        scores.append(100 if pct < 80 else (40 if pct < 95 else 10))

    # 2.3 Violations
    vio_results = splunk_search_oneshot(
        'search index=_internal source=*license_usage.log '
        'type=RolloverSummary earliest=-30d '
        '| where slaves_usage_bytes>quota '
        '| stats count as violations | table violations'
    )
    vio_count = 0
    if vio_results:
        vio_count = safe_int(vio_results[0].get("violations", 0))
    if vio_count > 5:
        record_finding("licensing", "Licensing", "violations",
                       "License Violations", "{} in 30d".format(vio_count),
                       "CRITICAL", "License block imminent at 5 violations in 30d window", 10,
                       fix_prompt="There are {} license violations in the last 30 days. "
                       "Splunk will block search at 5 violations. Immediately reduce "
                       "ingestion or increase license quota. Find top sources: "
                       "index=_internal source=*license_usage.log type=Usage | stats sum(b) by s | sort -sum(b)".format(vio_count))
        scores.append(10)
    elif vio_count > 0:
        record_finding("licensing", "Licensing", "violations",
                       "License Violations", "{} in 30d".format(vio_count),
                       "WARNING", "Approaching license block threshold", 50,
                       fix_prompt="{} license violation(s) detected. Review daily ingestion "
                       "volumes and identify spike sources. Consider adjusting "
                       "inputs.conf for noisy sources.".format(vio_count))
        scores.append(50)
    else:
        record_finding("licensing", "Licensing", "violations",
                       "License Violations", "0 in 30d", "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("licensing", "Licensing", score, 10)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 3: Clustering
# ═══════════════════════════════════════════════════════════════════════════

def audit_clustering():
    scores = []

    cluster_data = splunk_rest("/services/cluster/config", {"output_mode": "json"})
    entries = cluster_data.get("entry", [])
    if entries:
        mode = entries[0].get("content", {}).get("mode", "disabled")
        if mode == "disabled":
            record_finding("clustering", "Clustering", "cluster_mode",
                           "Cluster Mode", "Standalone (no clustering)",
                           "OK", "Single node — clustering N/A", 100)
        else:
            record_finding("clustering", "Clustering", "cluster_mode",
                           "Cluster Mode", "Mode: {}".format(mode),
                           "OK", "", 100)
    else:
        record_finding("clustering", "Clustering", "cluster_mode",
                       "Cluster Mode", "Standalone (no clustering)",
                       "OK", "Single node — clustering N/A", 100)
    scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("clustering", "Clustering", score, 10)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 4: Apps
# ═══════════════════════════════════════════════════════════════════════════

def audit_apps():
    scores = []

    # 4.1 App count
    apps_data = splunk_rest("/services/apps/local",
                            {"output_mode": "json", "count": "0"})
    app_entries = apps_data.get("entry", [])
    app_count = len(app_entries)

    BUNDLED_APPS = {
        "cyber_security_essentials_avert", "legacy", "sample_app",
        "splunk_archiver", "SplunkForwarder", "SplunkLightForwarder",
        "SplunkDeploymentServerConfig", "splunk_internal_metrics",
        "splunk_metrics_workspace", "splunk_rapid_diag", "splunk_gdi",
        "journald_input", "introspection_generator_addon",
    }
    disabled_apps = [e.get("name", "?") for e in app_entries
                     if e.get("content", {}).get("disabled", False)
                     and e.get("name", "") not in BUNDLED_APPS]

    if app_count > 50:
        record_finding("apps", "Apps", "app_count", "App Count",
                       "{} apps installed".format(app_count),
                       "INFO", "High app count — review for unused", 70,
                       fix_prompt="{} apps installed. Review and remove unused apps to reduce "
                       "config complexity. List all: $SPLUNK_HOME/bin/splunk display app".format(app_count))
        scores.append(70)
    else:
        record_finding("apps", "Apps", "app_count", "App Count",
                       "{} apps installed".format(app_count), "OK", "", 100)
        scores.append(100)

    # 4.2 Disabled apps
    if disabled_apps:
        record_finding("apps", "Apps", "disabled_apps", "Disabled Apps",
                       "{} disabled".format(len(disabled_apps)),
                       "INFO", ", ".join(disabled_apps[:5]),
                       80 if len(disabled_apps) < 5 else 60,
                       fix_prompt="Disabled apps found: {}. Consider removing apps that "
                       "are permanently disabled to reduce conf load.".format(", ".join(disabled_apps[:10])))
        scores.append(80 if len(disabled_apps) < 5 else 60)

    # 4.3 btool check — only count lines with "No spec file" (real warnings)
    btool_raw = run_cmd(
        "{}/bin/splunk btool check --debug 2>&1 | "
        "grep -i 'No spec file' | "
        "grep -v -i 'cyber_security\\|compliance_essentials\\|Splunk_AI_Assistant\\|splunk_assist\\|Splunk_ML_Toolkit' | "
        "head -10".format(SPLUNK_HOME)
    )
    btool_lines = [l for l in btool_raw.splitlines() if l.strip()]
    btool_count = len(btool_lines)
    if btool_count > 0:
        sample = btool_lines[0].strip()[:120] if btool_lines else ""
        record_finding("apps", "Apps", "btool_check", "Config Validation",
                       "{} missing spec files".format(btool_count), "WARNING",
                       sample, 60,
                       fix_prompt="btool found {} conf files without matching spec files: '{}'. "
                       "Add README/*.conf.spec files for custom confs, or remove "
                       "unused conf files.".format(btool_count, sample))
        scores.append(60)
    else:
        record_finding("apps", "Apps", "btool_check", "Config Validation",
                       "Clean", "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("apps", "Apps", score, 10)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 5: Usage
# ═══════════════════════════════════════════════════════════════════════════

def audit_usage():
    scores = []

    # 5.1 Scheduled search count
    ss_results = splunk_search_oneshot(
        '| rest /services/saved/searches splunk_server=local '
        '| search is_scheduled=1 disabled=0 '
        '| stats count as total | table total'
    )
    ss_count = 0
    if ss_results:
        ss_count = safe_int(ss_results[0].get("total", 0))

    if ss_count > 100:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "WARNING", "High count — scheduling pressure", 40,
                       fix_prompt="{} scheduled searches are active. Review and disable unused ones. "
                       "Check for overlapping schedules: "
                       "| rest /services/saved/searches | search is_scheduled=1 disabled=0 "
                       "| table title cron_schedule dispatch.earliest_time".format(ss_count))
        scores.append(40)
    elif ss_count > 50:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "INFO", "Moderate count", 65)
        scores.append(65)
    else:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "OK", "", 100)
        scores.append(100)

    # 5.2 Skipped searches (last 24h)
    skip_results = splunk_search_oneshot(
        'search index=_internal sourcetype=scheduler status=skipped earliest=-24h '
        '| stats dc(savedsearch_name) as skipped_names count as skipped_count '
        '| table skipped_names skipped_count'
    )
    skip_count = 0
    skip_names = 0
    if skip_results:
        skip_count = safe_int(skip_results[0].get("skipped_count", 0))
        skip_names = safe_int(skip_results[0].get("skipped_names", 0))

    if skip_count > 50:
        record_finding("usage", "Usage", "skipped_searches",
                       "Skipped Searches",
                       "{} skips across {} searches in 24h".format(skip_count, skip_names),
                       "WARNING", "Scheduler overloaded — searches being dropped", 35,
                       fix_prompt="{} scheduled search executions were skipped in 24h across {} "
                       "unique searches. This means the scheduler cannot keep up. Reduce "
                       "scheduled search count, stagger cron schedules, or increase "
                       "max_searches_per_cpu. Check: index=_internal sourcetype=scheduler "
                       "status=skipped | top savedsearch_name".format(skip_count, skip_names))
        scores.append(35)
    elif skip_count > 0:
        record_finding("usage", "Usage", "skipped_searches",
                       "Skipped Searches",
                       "{} skips in 24h".format(skip_count),
                       "INFO", "{} unique searches affected".format(skip_names), 70,
                       fix_prompt="{} scheduler skips detected. Stagger cron schedules "
                       "to reduce peak load.".format(skip_count))
        scores.append(70)
    else:
        record_finding("usage", "Usage", "skipped_searches",
                       "Skipped Searches", "0 skips in 24h", "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("usage", "Usage", score, 10)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 6: Search Performance
# ═══════════════════════════════════════════════════════════════════════════

def audit_search_performance():
    scores = []

    # 6.1 Long-running searches
    long_results = splunk_search_oneshot(
        'search index=_audit action=search info=completed earliest=-7d '
        '| where total_run_time>600 '
        '| stats count as long_count | table long_count'
    )
    long_count = safe_int(long_results[0].get("long_count", 0)) if long_results else 0

    if long_count > 10:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches",
                       "{} searches >600s in 7d".format(long_count),
                       "CRITICAL", "Excessive long-running searches", 15,
                       fix_prompt="{} searches ran longer than 10 minutes in the past week. "
                       "Find and optimize them: index=_audit action=search info=completed "
                       "| where total_run_time>600 | stats count by savedsearch_name user "
                       "| sort -count".format(long_count))
        scores.append(15)
    elif long_count > 0:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches",
                       "{} searches >600s in 7d".format(long_count),
                       "WARNING", "Some long-running searches detected", 50,
                       fix_prompt="{} searches exceeded 10 minutes. Review with: "
                       "index=_audit action=search info=completed | where total_run_time>600 "
                       "| table user savedsearch_name total_run_time".format(long_count))
        scores.append(50)
    else:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches", "None >600s", "OK", "", 100)
        scores.append(100)

    # 6.2 Real-time searches
    rt_results = splunk_search_oneshot(
        '| rest /services/search/jobs splunk_server=local '
        '| search isRealTimeSearch=1 '
        '| stats count as rt_count | table rt_count'
    )
    rt_count = safe_int(rt_results[0].get("rt_count", 0)) if rt_results else 0

    if rt_count > 10:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches", "{} active".format(rt_count),
                       "CRITICAL", "Excessive RT searches — high resource consumption", 15,
                       fix_prompt="{} real-time searches running. Each holds resources continuously. "
                       "Convert to scheduled searches where possible.".format(rt_count))
        scores.append(15)
    elif rt_count > 3:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches", "{} active".format(rt_count),
                       "WARNING", "Multiple RT searches active", 45,
                       fix_prompt="{} real-time searches active. Consider converting to "
                       "scheduled searches with short intervals.".format(rt_count))
        scores.append(45)
    elif rt_count > 0:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches", "{} active".format(rt_count),
                       "INFO", "", 70)
        scores.append(70)
    else:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches", "0 active", "OK", "", 100)
        scores.append(100)

    # 6.3 Search concurrency (only running jobs, not finished artifacts)
    jobs_results = splunk_search_oneshot(
        '| rest /services/search/jobs splunk_server=local '
        '| search dispatchState=RUNNING OR dispatchState=QUEUED OR dispatchState=PARSING '
        '| stats count as active | table active'
    )
    active_count = safe_int(jobs_results[0].get("active", 0)) if jobs_results else 0

    cores_str = run_cmd("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4")
    cores = safe_int(cores_str, 4)
    max_searches = cores * 2 + 6

    if active_count > max_searches * 90 // 100:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "{} of {} limit ({}%)".format(active_count, max_searches, active_count*100//max_searches),
                       "CRITICAL", ">90% of concurrent search limit", 15,
                       fix_prompt="Search concurrency at {}% of max ({}). Searches will queue. "
                       "Reduce concurrent load or increase max_searches_per_cpu in limits.conf.".format(
                           active_count*100//max_searches, max_searches))
        scores.append(15)
    elif active_count > max_searches * 70 // 100:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "{} of {} limit ({}%)".format(active_count, max_searches, active_count*100//max_searches),
                       "WARNING", ">70% of max — risk of queuing", 40,
                       fix_prompt="Search concurrency at {}%. Stagger scheduled searches "
                       "and review for unnecessary concurrent load.".format(active_count*100//max_searches))
        scores.append(40)
    else:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "{} of {} limit".format(active_count, max_searches),
                       "OK", "", 100)
        scores.append(100)

    # 6.4 Wildcard index=* searches (exclude DM accelerations and system)
    wildcard_results = splunk_search_oneshot(
        'search index=_audit action=search info=granted earliest=-7d '
        '| regex search="index\\s*=\\s*\\*" '
        '| where NOT match(savedsearch_name, "^_ACCELERATE_") '
        '| where user!="splunk-system-user" OR savedsearch_name!="" '
        '| stats dc(savedsearch_name) as saved_ct count as total '
        '| table saved_ct total'
    )
    wc_saved = safe_int(wildcard_results[0].get("saved_ct", 0)) if wildcard_results else 0
    wc_total = safe_int(wildcard_results[0].get("total", 0)) if wildcard_results else 0

    if wc_saved > 3:
        record_finding("search", "Search Perf", "wildcard_index",
                       "Wildcard Searches",
                       "{} saved searches use index=*".format(wc_saved),
                       "CRITICAL", "Full scan pattern detected — scans all indexes", 15,
                       fix_prompt="{} saved searches use index=* which scans all indexes and "
                       "degrades performance. Replace with explicit index names. "
                       "Find them: | rest /services/saved/searches | search disabled=0 "
                       "| where like(search, \"%index=*%\") | table title eai:acl.app search".format(wc_saved))
        scores.append(15)
    elif wc_saved > 0:
        record_finding("search", "Search Perf", "wildcard_index",
                       "Wildcard Searches",
                       "{} saved searches use index=*".format(wc_saved),
                       "WARNING", "Full scan pattern — replace with specific indexes", 50,
                       fix_prompt="{} saved searches use index=*. Replace with explicit index names "
                       "for better performance.".format(wc_saved))
        scores.append(50)
    else:
        record_finding("search", "Search Perf", "wildcard_index",
                       "Wildcard Searches", "No index=* patterns", "OK", "", 100)
        scores.append(100)

    # 6.5 Dispatch directory size
    dispatch_raw = run_cmd("du -sm {}/var/run/splunk/dispatch 2>/dev/null".format(SPLUNK_HOME))
    dispatch_mb = 0
    if dispatch_raw:
        parts = dispatch_raw.strip().split()
        if parts:
            dispatch_mb = safe_int(parts[0], 0)
    dispatch_gb = round(dispatch_mb / 1024.0, 1)

    if dispatch_mb > 10240:
        record_finding("search", "Search Perf", "dispatch_dir",
                       "Dispatch Dir", "{} GB".format(dispatch_gb),
                       "CRITICAL", "dispatch >10GB — cleanup needed", 15,
                       fix_prompt="Dispatch directory is {} GB. Clean old artifacts: "
                       "find $SPLUNK_HOME/var/run/splunk/dispatch -maxdepth 1 -type d "
                       "-mtime +3 -exec rm -rf {{}} +".format(dispatch_gb))
        scores.append(15)
    elif dispatch_mb > 5120:
        record_finding("search", "Search Perf", "dispatch_dir",
                       "Dispatch Dir", "{} GB".format(dispatch_gb),
                       "WARNING", "dispatch growing large", 50,
                       fix_prompt="Dispatch directory at {} GB. Consider reducing "
                       "default_save_ttl in limits.conf and cleaning stale jobs.".format(dispatch_gb))
        scores.append(50)
    else:
        record_finding("search", "Search Perf", "dispatch_dir",
                       "Dispatch Dir", "{} GB".format(dispatch_gb),
                       "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("search", "Search Perf", score, 20)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 7: Dashboards
# ═══════════════════════════════════════════════════════════════════════════

def audit_dashboards():
    scores = []

    dash_data = splunk_rest("/servicesNS/-/-/data/ui/views",
                            {"output_mode": "json", "count": "0",
                             "search": "isDashboard=1 AND isVisible=1"})
    entries = dash_data.get("entry", [])

    studio = 0
    classic = 0
    for entry in entries:
        content = entry.get("content", {})
        eai_data = content.get("eai:data", "")
        if 'version="2"' in eai_data or "version='2'" in eai_data:
            studio += 1
        else:
            classic += 1

    total = studio + classic
    if total > 0:
        ratio = round(studio / total * 100)
        record_finding("dashboards", "Dashboards", "studio_ratio",
                       "Studio v2 Ratio",
                       "{}/{} Studio v2 ({}%)".format(studio, total, ratio),
                       "OK" if ratio > 50 else "INFO",
                       "" if ratio > 50 else "Most dashboards are Classic XML — consider migrating",
                       100 if ratio > 50 else 70,
                       fix_prompt="" if ratio > 50 else
                       "{} of {} dashboards are Classic XML. Consider migrating to "
                       "Dashboard Studio v2 for better performance and features.".format(classic, total))
        scores.append(100 if ratio > 50 else 70)
    else:
        record_finding("dashboards", "Dashboards", "studio_ratio",
                       "Studio v2 Ratio", "No dashboards found", "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("dashboards", "Dashboards", score, 10)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN 8: Indexes
# ═══════════════════════════════════════════════════════════════════════════

def audit_indexes():
    scores = []

    idx_data = splunk_rest("/services/data/indexes",
                           {"output_mode": "json", "count": "0"})
    entries = idx_data.get("entry", [])

    active_count = 0
    total_mb = 0.0
    dead_count = 0
    dead_names = []
    no_retention = []

    for entry in entries:
        c = entry.get("content", {})
        name = entry.get("name", "")
        evts = safe_int(c.get("totalEventCount", 0))
        disabled = c.get("disabled", False)
        size = safe_float(c.get("currentDBSizeMB", 0))
        frozen = safe_int(c.get("frozenTimePeriodInSecs", 0))

        if evts > 0:
            active_count += 1
            total_mb += size
        elif not disabled and not name.startswith("_") \
                and name not in ("history", "summary"):
            dead_count += 1
            dead_names.append(name)

        if frozen == 0 and not disabled and not name.startswith("_"):
            no_retention.append(name)

    total_gb = round(total_mb / 1024.0, 1)

    record_finding("indexes", "Indexes", "total_size", "Total Index Size",
                   "{} GB across {} active indexes".format(total_gb, active_count),
                   "OK", "", 100)
    scores.append(100)

    if dead_count > 0:
        record_finding("indexes", "Indexes", "dead_indexes", "Dead Indexes",
                       "{} empty non-internal indexes".format(dead_count),
                       "INFO", ", ".join(dead_names[:8]),
                       80 if dead_count < 5 else 60,
                       fix_prompt="Empty indexes found: {}. These consume config overhead. "
                       "Remove if unused or verify data inputs are configured correctly.".format(
                           ", ".join(dead_names[:10])))
        scores.append(80 if dead_count < 5 else 60)
    else:
        record_finding("indexes", "Indexes", "dead_indexes", "Dead Indexes",
                       "0 empty indexes", "OK", "", 100)
        scores.append(100)

    if no_retention:
        record_finding("indexes", "Indexes", "retention", "Retention Policy",
                       "{} indexes without explicit retention".format(len(no_retention)),
                       "INFO", ", ".join(no_retention[:8]),
                       70,
                       fix_prompt="Indexes without frozenTimePeriodInSecs: {}. "
                       "Set retention in indexes.conf to control disk growth.".format(
                           ", ".join(no_retention[:10])))
        scores.append(70)
    else:
        record_finding("indexes", "Indexes", "retention", "Retention Policy",
                       "All indexes have retention set", "OK", "", 100)
        scores.append(100)

    score = calc_domain_score(scores)
    record_domain_score("indexes", "Indexes", score, 15)
    return score


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    sys.stderr.write("SPLUNK-BOT audit_runner.py starting at {}\n".format(NOW))

    get_session_key()
    if not SESSION_KEY:
        sys.stderr.write("ERROR: Could not obtain session key\n")
        sys.exit(1)

    audit_system_health()
    audit_licensing()
    audit_clustering()
    audit_apps()
    audit_usage()
    audit_search_performance()
    audit_dashboards()
    audit_indexes()

    total = CRITICAL_COUNT + WARNING_COUNT + INFO_COUNT + OK_COUNT
    if CRITICAL_COUNT > 0:
        overall_status = "CRITICAL"
    elif WARNING_COUNT > 0:
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    overall_score = 0
    for ds in DOMAIN_SCORES:
        overall_score += int(ds.get("weighted_score", 0))

    summary = {
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": _hostname(),
        "splunk_version": SPLUNK_VER,
        "event_type": "summary",
        "overall_score": overall_score,
        "overall_status": overall_status,
        "critical_count": CRITICAL_COUNT,
        "warning_count": WARNING_COUNT,
        "info_count": INFO_COUNT,
        "ok_count": OK_COUNT,
        "domains_audited": 8,
    }

    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)
    out_path = os.path.join(AUDIT_LOG_DIR, "audit_{}.json".format(TODAY))

    with open(out_path, "w") as f:
        f.write(json.dumps(summary) + "\n")
        for ds in DOMAIN_SCORES:
            f.write(json.dumps(ds) + "\n")
        for finding in FINDINGS:
            f.write(json.dumps(finding) + "\n")

    sys.stderr.write(
        "SPLUNK-BOT audit complete: score={} status={} findings={} "
        "output={}\n".format(overall_score, overall_status, total, out_path)
    )


if __name__ == "__main__":
    main()

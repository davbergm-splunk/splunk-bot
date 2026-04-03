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
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
import ssl
import base64
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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = "https://{}:{}/services/auth/login".format(SPLUNK_HOST, SPLUNK_MGMT_PORT)
    data = "username={}&password={}&output_mode=json".format(
        urllib.parse.quote(user), urllib.parse.quote(password)
    ).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    resp = urllib.request.urlopen(req, context=ctx)
    body = json.loads(resp.read().decode("utf-8"))
    return body.get("sessionKey", "")


def splunk_rest(endpoint, params=None, method="GET"):
    """Call Splunk REST API and return parsed JSON."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = "https://{}:{}{}".format(SPLUNK_HOST, SPLUNK_MGMT_PORT, endpoint)
    if params:
        url += "?" + urllib.parse.urlencode(params)

    key = get_session_key()
    if not key:
        return {}

    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Splunk {}".format(key))
    req.add_header("Content-Type", "application/json")

    try:
        resp = urllib.request.urlopen(req, context=ctx)
        return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError:
        return {}
    except Exception:
        return {}


def splunk_search_oneshot(spl, max_count=100):
    """Run a oneshot search and return results."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

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
        resp = urllib.request.urlopen(req, context=ctx)
        body = json.loads(resp.read().decode("utf-8"))
        return body.get("results", [])
    except Exception:
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


def record_finding(domain, domain_label, check, check_label, result,
                   severity, detail, score):
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

    FINDINGS.append({
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": run_cmd("hostname").split(".")[0] or "splunk",
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
    })


def record_domain_score(domain, domain_label, domain_score, weight):
    """Record a domain score."""
    weighted = round(domain_score * weight / 100.0, 1)
    DOMAIN_SCORES.append({
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": run_cmd("hostname").split(".")[0] or "splunk",
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
        record_finding("system_health", "System Health", "splunk_version",
                       "Splunk Version", "{} build {}".format(SPLUNK_VER, build),
                       "OK", "", 100)
    else:
        record_finding("system_health", "System Health", "splunk_version",
                       "Splunk Version", "unknown", "INFO",
                       "Could not query server info", 70)
    scores.append(100)

    # 1.2 CPU / RAM
    cores = run_cmd("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 0")
    mem_raw = run_cmd("free -g 2>/dev/null | grep Mem || echo ''")
    if mem_raw:
        parts = mem_raw.split()
        total_gb = parts[1] if len(parts) > 1 else "?"
        avail_gb = parts[6] if len(parts) > 6 else parts[-1] if len(parts) > 1 else "?"
        try:
            avail_int = int(avail_gb)
            if avail_int < 2:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM", "{} cores, {}GB total, {}GB avail".format(
                                   cores, total_gb, avail_gb),
                               "CRITICAL", "Available RAM critically low", 10)
                scores.append(10)
            elif avail_int < 4:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM", "{} cores, {}GB total, {}GB avail".format(
                                   cores, total_gb, avail_gb),
                               "WARNING", "<4 GB available", 45)
                scores.append(45)
            else:
                record_finding("system_health", "System Health", "cpu_ram",
                               "CPU/RAM", "{} cores, {}GB total, {}GB avail".format(
                                   cores, total_gb, avail_gb),
                               "OK", "", 100)
                scores.append(100)
        except ValueError:
            record_finding("system_health", "System Health", "cpu_ram",
                           "CPU/RAM", "{} cores (RAM parse failed)".format(cores),
                           "INFO", "Could not parse memory info", 70)
            scores.append(70)
    else:
        record_finding("system_health", "System Health", "cpu_ram",
                       "CPU/RAM", "{} cores (RAM N/A)".format(cores),
                       "INFO", "No free command", 70)
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
                       "CRITICAL", "$SPLUNK_HOME partition critically full", 5)
        scores.append(5)
    elif disk_pct > 85:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "WARNING", "$SPLUNK_HOME >85% full", 30)
        scores.append(30)
    elif disk_pct > 75:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "WARNING", "$SPLUNK_HOME >75% full", 40)
        scores.append(40)
    elif disk_pct > 0:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "{}% used".format(disk_pct),
                       "OK", "", 100)
        scores.append(100)
    else:
        record_finding("system_health", "System Health", "disk_space",
                       "Disk Space", "Unable to determine", "INFO",
                       "Could not parse df output", 70)
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
                               "CRITICAL", "dispatch >50GB", 5)
                scores.append(5)
            elif gb > 10:
                record_finding("system_health", "System Health", "dispatch_dir",
                               "Dispatch Dir", dispatch_size,
                               "CRITICAL", "dispatch >10GB", 10)
                scores.append(10)
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
        kv_status = kv_entries[0].get("content", {}).get("current", {}).get("status", "unknown")
    if kv_status == "ready":
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", "Ready", "OK", "", 100)
        scores.append(100)
    elif kv_status in ("down", "degraded"):
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", kv_status.title(),
                       "CRITICAL", "KV store not operational", 10)
        scores.append(10)
    else:
        record_finding("system_health", "System Health", "kvstore",
                       "KV Store", kv_status, "INFO", "", 70)
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
    if lic_type == "Enterprise":
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Enterprise", "OK", "", 100)
        scores.append(100)
    elif lic_type == "Trial":
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Trial", "WARNING",
                       "Trial license — temporary", 50)
        scores.append(50)
    else:
        record_finding("licensing", "Licensing", "license_type",
                       "License Type", "Free/Unknown", "INFO", "", 70)
        scores.append(70)

    # 2.2 Violations
    vio_results = splunk_search_oneshot(
        'search index=_internal source=*license_usage.log '
        'type=RolloverSummary earliest=-30d '
        '| where slaves_usage_bytes>quota '
        '| stats count as violations | table violations'
    )
    vio_count = 0
    if vio_results:
        vio_count = int(vio_results[0].get("violations", 0))
    if vio_count > 5:
        record_finding("licensing", "Licensing", "violations",
                       "License Violations", "{} in 30d".format(vio_count),
                       "CRITICAL", "License block imminent", 10)
        scores.append(10)
    elif vio_count > 0:
        record_finding("licensing", "Licensing", "violations",
                       "License Violations", "{} in 30d".format(vio_count),
                       "WARNING", "", 50)
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
                            {"output_mode": "json", "count": 0})
    app_count = len(apps_data.get("entry", []))
    if app_count > 50:
        record_finding("apps", "Apps", "app_count", "App Count",
                       "{} apps installed".format(app_count),
                       "INFO", "High app count — review for unused", 70)
        scores.append(70)
    else:
        record_finding("apps", "Apps", "app_count", "App Count",
                       "{} apps installed".format(app_count), "OK", "", 100)
        scores.append(100)

    # 4.2 btool check
    btool_raw = run_cmd(
        "{}/bin/splunk btool check --debug 2>&1 | "
        "grep -v 'cyber_security\\|compliance_essentials\\|Splunk_AI_Assistant' | "
        "head -20".format(SPLUNK_HOME)
    )
    btool_count = len([l for l in btool_raw.splitlines() if l.strip()])
    if btool_count > 0:
        record_finding("apps", "Apps", "btool_check", "Config Validation",
                       "{} warnings".format(btool_count), "WARNING",
                       "btool check found config issues", 50)
        scores.append(50)
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

    ss_results = splunk_search_oneshot(
        '| rest /services/saved/searches '
        '| search is_scheduled=1 disabled=0 '
        '| stats count as total | table total'
    )
    ss_count = 0
    if ss_results:
        ss_count = int(ss_results[0].get("total", 0))

    if ss_count > 100:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "WARNING", "High count — scheduling pressure", 40)
        scores.append(40)
    elif ss_count > 50:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "INFO", "", 65)
        scores.append(65)
    else:
        record_finding("usage", "Usage", "saved_searches",
                       "Scheduled Searches", "{} enabled".format(ss_count),
                       "OK", "", 100)
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
    long_count = 0
    if long_results:
        long_count = int(long_results[0].get("long_count", 0))

    if long_count > 10:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches",
                       "{} searches >600s".format(long_count),
                       "CRITICAL", "Excessive long-running searches", 15)
        scores.append(15)
    elif long_count > 0:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches",
                       "{} searches >600s".format(long_count),
                       "WARNING", "", 40)
        scores.append(40)
    else:
        record_finding("search", "Search Perf", "long_running",
                       "Long Running Searches", "None >600s", "OK", "", 100)
        scores.append(100)

    # 6.2 Real-time searches
    rt_results = splunk_search_oneshot(
        '| rest /services/search/jobs '
        '| search isRealTimeSearch=1 '
        '| stats count as rt_count | table rt_count'
    )
    rt_count = 0
    if rt_results:
        rt_count = int(rt_results[0].get("rt_count", 0))

    if rt_count > 10:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches",
                       "{} active".format(rt_count),
                       "CRITICAL", "Excessive RT searches", 15)
        scores.append(15)
    elif rt_count > 3:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches",
                       "{} active".format(rt_count), "WARNING", "", 45)
        scores.append(45)
    elif rt_count > 0:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches",
                       "{} active".format(rt_count), "INFO", "", 70)
        scores.append(70)
    else:
        record_finding("search", "Search Perf", "realtime",
                       "Real-Time Searches", "0 active", "OK", "", 100)
        scores.append(100)

    # 6.3 Search concurrency
    jobs_results = splunk_search_oneshot(
        '| rest /services/search/jobs '
        '| stats count as active | table active'
    )
    active_count = 0
    if jobs_results:
        active_count = int(jobs_results[0].get("active", 0))

    cores_str = run_cmd("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4")
    try:
        cores = int(cores_str)
    except ValueError:
        cores = 4
    max_searches = cores * 2 + 6

    if active_count > max_searches * 90 // 100:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "Peak {} of {} limit".format(active_count, max_searches),
                       "CRITICAL", ">90% of max", 15)
        scores.append(15)
    elif active_count > max_searches * 70 // 100:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "Peak {} of {} limit".format(active_count, max_searches),
                       "WARNING", ">70% of max — risk of queuing", 40)
        scores.append(40)
    else:
        record_finding("search", "Search Perf", "concurrency",
                       "Search Concurrency",
                       "{} of {} limit".format(active_count, max_searches),
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

    dash_results = splunk_search_oneshot(
        '| rest /servicesNS/-/-/data/ui/views '
        '| search isDashboard=1 '
        '| eval type=if(like(eai:data, "%version=\\"2\\"%"), '
        '"studio_v2", "classic_xml") '
        '| stats count by type | table type count'
    )
    studio = 0
    classic = 0
    for row in dash_results:
        t = row.get("type", "")
        c = int(row.get("count", 0))
        if "studio" in t:
            studio = c
        elif "classic" in t:
            classic = c
    total = studio + classic

    record_finding("dashboards", "Dashboards", "studio_ratio",
                   "Studio v2 Ratio",
                   "{}/{} Studio v2".format(studio, total), "OK", "", 100)
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
                           {"output_mode": "json", "count": 0})
    entries = idx_data.get("entry", [])

    active_count = 0
    total_mb = 0
    dead_count = 0
    for entry in entries:
        c = entry.get("content", {})
        evts = int(c.get("totalEventCount", 0))
        disabled = c.get("disabled", False)
        size = float(c.get("currentDBSizeMB", 0))
        if evts > 0:
            active_count += 1
            total_mb += size
        elif not disabled:
            dead_count += 1

    total_gb = round(total_mb / 1024.0, 1)

    record_finding("indexes", "Indexes", "total_size", "Total Index Size",
                   "{} GB across {} indexes".format(total_gb, active_count),
                   "OK", "", 100)
    scores.append(100)

    if dead_count > 0:
        record_finding("indexes", "Indexes", "dead_indexes", "Dead Indexes",
                       "{} empty indexes".format(dead_count),
                       "INFO", "Candidates for removal", 70)
        scores.append(70)
    else:
        record_finding("indexes", "Indexes", "dead_indexes", "Dead Indexes",
                       "0 dead indexes", "OK", "", 100)
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

    hostname = run_cmd("hostname").split(".")[0] or "splunk"

    summary = {
        "audit_time": NOW,
        "audit_id": AUDIT_ID,
        "host": hostname,
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

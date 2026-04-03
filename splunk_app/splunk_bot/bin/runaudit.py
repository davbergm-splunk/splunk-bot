"""
SPLUNK-BOT custom search command: | runaudit

Executes the audit_runner inline and returns results as a search result
table so the dashboard can trigger and display status.

Splunk protocol for custom search commands with passauth:
  - Line 1 of stdin: the auth token (session key)
  - Remaining stdin: CSV data (empty for generating commands)
"""

import csv
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_runner


def read_session_key():
    """Read the session key that Splunk passes as the first line of stdin
    when passauth is configured in commands.conf."""

    if not sys.stdin.isatty():
        first_line = sys.stdin.readline().strip()
        if first_line:
            return first_line

    return os.environ.get("SPLUNK_SESSION_KEY", "")


def main():
    session_key = read_session_key()

    # Drain any remaining stdin
    try:
        sys.stdin.read()
    except Exception:
        pass

    if session_key:
        audit_runner.SESSION_KEY = session_key
    else:
        audit_runner.get_session_key()

    if not audit_runner.SESSION_KEY:
        writer = csv.DictWriter(sys.stdout, fieldnames=["status", "message"])
        writer.writeheader()
        writer.writerow({
            "status": "ERROR",
            "message": "Could not obtain session key"
        })
        return

    audit_runner.audit_system_health()
    audit_runner.audit_licensing()
    audit_runner.audit_clustering()
    audit_runner.audit_apps()
    audit_runner.audit_usage()
    audit_runner.audit_search_performance()
    audit_runner.audit_dashboards()
    audit_runner.audit_indexes()

    total = (audit_runner.CRITICAL_COUNT + audit_runner.WARNING_COUNT +
             audit_runner.INFO_COUNT + audit_runner.OK_COUNT)

    if audit_runner.CRITICAL_COUNT > 0:
        overall_status = "CRITICAL"
    elif audit_runner.WARNING_COUNT > 0:
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    overall_score = 0
    for ds in audit_runner.DOMAIN_SCORES:
        overall_score += int(ds.get("weighted_score", 0))

    hostname = audit_runner.run_cmd("hostname").split(".")[0] or "splunk"

    summary = {
        "audit_time": audit_runner.NOW,
        "audit_id": audit_runner.AUDIT_ID,
        "host": hostname,
        "splunk_version": audit_runner.SPLUNK_VER,
        "event_type": "summary",
        "overall_score": overall_score,
        "overall_status": overall_status,
        "critical_count": audit_runner.CRITICAL_COUNT,
        "warning_count": audit_runner.WARNING_COUNT,
        "info_count": audit_runner.INFO_COUNT,
        "ok_count": audit_runner.OK_COUNT,
        "domains_audited": 8,
    }

    out_dir = audit_runner.AUDIT_LOG_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "audit_{}.json".format(audit_runner.TODAY))

    with open(out_path, "w") as f:
        f.write(json.dumps(summary) + "\n")
        for ds in audit_runner.DOMAIN_SCORES:
            f.write(json.dumps(ds) + "\n")
        for finding in audit_runner.FINDINGS:
            f.write(json.dumps(finding) + "\n")

    fields = ["status", "score", "findings", "critical", "warning",
              "info", "ok", "output_file"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields)
    writer.writeheader()
    writer.writerow({
        "status": overall_status,
        "score": overall_score,
        "findings": total,
        "critical": audit_runner.CRITICAL_COUNT,
        "warning": audit_runner.WARNING_COUNT,
        "info": audit_runner.INFO_COUNT,
        "ok": audit_runner.OK_COUNT,
        "output_file": out_path,
    })


if __name__ == "__main__":
    main()

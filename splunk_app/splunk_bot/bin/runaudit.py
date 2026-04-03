"""
SPLUNK-BOT custom search command: | runaudit

Executes the audit_runner and returns results as a search result table.

Auth strategy: Since Splunk's passauth session keys cannot call REST
endpoints, this script authenticates itself by reading admin credentials
from $SPLUNK_HOME/etc/apps/splunk_bot/local/audit_creds.conf. This file
is NOT shipped with the app — create it on the Splunk host:

  [auth]
  username = admin
  password = <your_admin_password>
"""

import configparser
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_runner


SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
CREDS_PATH = os.path.join(
    SPLUNK_HOME, "etc", "apps", "splunk_bot", "local", "audit_creds.conf"
)


def get_admin_session_key():
    """Authenticate as admin by reading local credentials file."""
    if not os.path.exists(CREDS_PATH):
        sys.stderr.write("audit_creds.conf not found at {}\n".format(CREDS_PATH))
        return None

    cfg = configparser.ConfigParser()
    cfg.read(CREDS_PATH)

    user = cfg.get("auth", "username", fallback="admin")
    password = cfg.get("auth", "password", fallback="")
    if not password:
        sys.stderr.write("No password in audit_creds.conf\n")
        return None

    try:
        return audit_runner.auth_with_password(user, password)
    except Exception as e:
        sys.stderr.write("Auth failed: {}\n".format(e))
        return None


def main():
    # Drain stdin (passauth sends session key on line 1, but we don't use it)
    if not sys.stdin.isatty():
        try:
            sys.stdin.read()
        except Exception:
            pass

    session_key = get_admin_session_key()
    if session_key:
        audit_runner.SESSION_KEY = session_key
    else:
        # Last resort: try passauth key from stdin (already drained, won't work)
        # or env var
        audit_runner.get_session_key()

    if not audit_runner.SESSION_KEY:
        writer = csv.DictWriter(sys.stdout, fieldnames=["status", "message"])
        writer.writeheader()
        writer.writerow({
            "status": "ERROR",
            "message": "Could not authenticate. Create "
                       "$SPLUNK_HOME/etc/apps/splunk_bot/local/audit_creds.conf "
                       "with [auth] username=admin password=<pass>"
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

    summary = {
        "audit_time": audit_runner.NOW,
        "audit_id": audit_runner.AUDIT_ID,
        "host": audit_runner._hostname(),
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

#!/usr/bin/env bash
set -euo pipefail

# Seeds sample audit data into the splunk_bot index for testing.
# Run after deploying the app and restarting Splunk.

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_USER="${SSH_USER:-dave}"
SSH_HOST="${SSH_HOST:-192.168.1.114}"
SPLUNK_HOME="${SPLUNK_HOME_REMOTE:-/opt/splunk}"

SSH_CMD="ssh -i $SSH_KEY $SSH_USER@$SSH_HOST"
AUDIT_DIR="$SPLUNK_HOME/var/log/splunk_bot"
NOW=$(date -u +%Y-%m-%dT%H:%M:%S%z)
TODAY=$(date +%Y-%m-%d)
AUDIT_ID="$TODAY"

echo "=== Seeding sample audit data ==="
echo "Timestamp: $NOW"
echo "Audit ID:  $AUDIT_ID"

$SSH_CMD "mkdir -p $AUDIT_DIR && cat > $AUDIT_DIR/audit_${TODAY}.json << 'JSONEOF'
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"summary\",\"overall_score\":63,\"overall_status\":\"WARNING\",\"critical_count\":2,\"warning_count\":5,\"info_count\":8,\"ok_count\":20,\"domains_audited\":8}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"domain_score\":70,\"domain_weight\":15,\"weighted_score\":10.5}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"licensing\",\"domain_label\":\"Licensing\",\"domain_score\":85,\"domain_weight\":10,\"weighted_score\":8.5}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"apps\",\"domain_label\":\"Apps\",\"domain_score\":60,\"domain_weight\":10,\"weighted_score\":6.0}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"search\",\"domain_label\":\"Search Perf\",\"domain_score\":45,\"domain_weight\":20,\"weighted_score\":9.0}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"dashboards\",\"domain_label\":\"Dashboards\",\"domain_score\":55,\"domain_weight\":10,\"weighted_score\":5.5}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"indexes\",\"domain_label\":\"Indexes\",\"domain_score\":80,\"domain_weight\":15,\"weighted_score\":12.0}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"usage\",\"domain_label\":\"Usage\",\"domain_score\":50,\"domain_weight\":10,\"weighted_score\":5.0}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"domain_score\",\"domain\":\"clustering\",\"domain_label\":\"Clustering\",\"domain_score\":90,\"domain_weight\":10,\"weighted_score\":9.0}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"splunk_version\",\"check_label\":\"Splunk Version\",\"result\":\"10.2.1 — current\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"disk_space\",\"check_label\":\"Disk Space\",\"result\":\"78% used\",\"severity\":\"WARNING\",\"detail\":\"$SPLUNK_HOME partition >75% full\",\"score\":40}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"dispatch_dir\",\"check_label\":\"Dispatch Dir\",\"result\":\"12.3 GB\",\"severity\":\"CRITICAL\",\"detail\":\"dispatch >10GB — cleanup needed\",\"score\":10}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"search\",\"domain_label\":\"Search Perf\",\"check\":\"long_running\",\"check_label\":\"Long Running Searches\",\"result\":\"3 searches >600s\",\"severity\":\"WARNING\",\"detail\":\"Top: full_inventory_lookup at 1842s\",\"score\":30}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"search\",\"domain_label\":\"Search Perf\",\"check\":\"wildcard_early\",\"check_label\":\"Wildcard Searches\",\"result\":\"7 searches use index=*\",\"severity\":\"CRITICAL\",\"detail\":\"Full scan pattern detected\",\"score\":15}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"search\",\"domain_label\":\"Search Perf\",\"check\":\"tstats_adoption\",\"check_label\":\"tstats Adoption\",\"result\":\"12% of queries use tstats\",\"severity\":\"INFO\",\"detail\":\"Low tstats usage — optimization opportunity\",\"score\":55}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"licensing\",\"domain_label\":\"Licensing\",\"check\":\"daily_usage\",\"check_label\":\"Daily Usage\",\"result\":\"2.1 GB/day avg (5 GB quota)\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"licensing\",\"domain_label\":\"Licensing\",\"check\":\"violations\",\"check_label\":\"License Violations\",\"result\":\"0 in 30d\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"apps\",\"domain_label\":\"Apps\",\"check\":\"btool_check\",\"check_label\":\"Config Validation\",\"result\":\"14 warnings\",\"severity\":\"WARNING\",\"detail\":\"14 btool warnings in user apps\",\"score\":50}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"apps\",\"domain_label\":\"Apps\",\"check\":\"disabled_apps\",\"check_label\":\"Disabled Apps\",\"result\":\"3 disabled apps\",\"severity\":\"INFO\",\"detail\":\"splunk_archiver, learned, introspection_generator_addon\",\"score\":70}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"dashboards\",\"domain_label\":\"Dashboards\",\"check\":\"panel_count\",\"check_label\":\"Panel Count\",\"result\":\"2 dashboards >10 panels\",\"severity\":\"WARNING\",\"detail\":\"unlox_health_hub (14), unlox_correlations (12)\",\"score\":45}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"dashboards\",\"domain_label\":\"Dashboards\",\"check\":\"studio_ratio\",\"check_label\":\"Studio v2 Ratio\",\"result\":\"8/8 Studio v2\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"indexes\",\"domain_label\":\"Indexes\",\"check\":\"dead_indexes\",\"check_label\":\"Dead Indexes\",\"result\":\"0 dead indexes\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"indexes\",\"domain_label\":\"Indexes\",\"check\":\"retention\",\"check_label\":\"Retention Policy\",\"result\":\"All indexes have retention set\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"usage\",\"domain_label\":\"Usage\",\"check\":\"unused_apps\",\"check_label\":\"Unused Apps\",\"result\":\"4 apps with 0 searches in 7d\",\"severity\":\"INFO\",\"detail\":\"alert_webhook, python_upgrade_readiness_app, splunk_essentials_9_0, splunk_secure_gateway\",\"score\":60}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"usage\",\"domain_label\":\"Usage\",\"check\":\"saved_search_overlap\",\"check_label\":\"Schedule Overlap\",\"result\":\"Peak 4 concurrent at 00:05\",\"severity\":\"INFO\",\"detail\":\"Within limits but could be spread\",\"score\":65}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"dashboards\",\"domain_label\":\"Dashboards\",\"check\":\"auto_refresh\",\"check_label\":\"Auto-Refresh\",\"result\":\"No dashboards <60s refresh\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"kvstore\",\"check_label\":\"KV Store\",\"result\":\"Ready, 42 MB\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"cpu_cores\",\"check_label\":\"CPU Cores\",\"result\":\"4 cores\",\"severity\":\"INFO\",\"detail\":\"Minimum for production — consider 8+\",\"score\":60}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"system_health\",\"domain_label\":\"System Health\",\"check\":\"memory\",\"check_label\":\"RAM\",\"result\":\"16 GB total, 3.2 GB available\",\"severity\":\"WARNING\",\"detail\":\"<4 GB available — monitor for pressure\",\"score\":45}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"clustering\",\"domain_label\":\"Clustering\",\"check\":\"cluster_mode\",\"check_label\":\"Cluster Mode\",\"result\":\"Standalone (no clustering)\",\"severity\":\"OK\",\"detail\":\"Single node — clustering N/A\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"indexes\",\"domain_label\":\"Indexes\",\"check\":\"total_size\",\"check_label\":\"Total Index Size\",\"result\":\"28.4 GB across 9 indexes\",\"severity\":\"OK\",\"detail\":\"\",\"score\":100}
{\"audit_time\":\"${NOW}\",\"audit_id\":\"${AUDIT_ID}\",\"host\":\"am06\",\"splunk_version\":\"10.2.1\",\"event_type\":\"finding\",\"domain\":\"search\",\"domain_label\":\"Search Perf\",\"check\":\"concurrency\",\"check_label\":\"Search Concurrency\",\"result\":\"Peak 6 of 8 limit\",\"severity\":\"WARNING\",\"detail\":\"75% of max — risk of queuing at peak\",\"score\":40}
JSONEOF"

echo "[OK] Sample data written to $AUDIT_DIR/audit_${TODAY}.json"
echo "Events should appear in index=splunk_bot within ~60 seconds"

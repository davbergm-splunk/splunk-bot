# SPLUNK-BOT

A retro terminal-themed Splunk app for platform health auditing. Scores your Splunk instance across 8 domains, rates findings by severity, and displays everything in a CRT green phosphor dashboard.

```
> SPLUNK-BOT v1.0.0 — Platform Audit Terminal
> ____________________________________________
>
> HEALTH_SCORE: 63 / 100
> SYS_STATUS:   WARNING
>
> >> CRITICAL: 2  >> WARNING: 5  >> INFO: 8  >> PASS: 20
>
> [scanning domains...]
```

## What It Does

SPLUNK-BOT performs a comprehensive health audit of a Splunk Enterprise instance across 8 domains:

| Domain | What It Checks |
|--------|---------------|
| **System Health** | CPU, RAM, disk, splunkd uptime, dispatch dir, KV store |
| **Licensing** | Quota usage, violations, pool efficiency |
| **Clustering** | Replication/search factor, peer health, SHC status |
| **Apps** | btool validation, disabled/deprecated apps, modular inputs |
| **Usage** | App adoption, saved search inventory, scheduling conflicts |
| **Search Perf** | Long-running queries, wildcard abuse, tstats adoption |
| **Dashboards** | Panel counts, time ranges, Studio v2 ratio, auto-refresh |
| **Indexes** | Sizes, retention, dead indexes, data model acceleration |

Each finding is scored 0-100 and classified by severity:

| Severity | Color | Meaning |
|----------|-------|---------|
| CRITICAL | Red | Service at risk, fix immediately |
| WARNING | Amber | Degraded performance, fix within 1 week |
| INFO | Cyan | Suboptimal but functional |
| OK | Green | Within healthy thresholds |

## Architecture

```
splunk-bot/
├── splunk_app/splunk_bot/       # The Splunk app
│   ├── default/
│   │   ├── app.conf             # App identity
│   │   ├── indexes.conf         # splunk_bot index
│   │   ├── inputs.conf          # File monitor for audit reports
│   │   ├── props.conf           # JSON parsing for audit events
│   │   └── data/ui/
│   │       ├── nav/default.xml  # Navigation
│   │       └── views/
│   │           └── bot_audit.xml  # Dashboard Studio v2 definition
│   ├── appserver/static/
│   │   └── terminal_bg.svg      # CRT phosphor background
│   ├── metadata/default.meta    # Permissions
│   └── bin/                     # (reserved for future scripts)
├── deploy/
│   ├── deploy_am06.sh           # Full deployment script
│   └── seed_sample_data.sh      # Seed test data for demo
├── .env.example                 # Credential template
├── .gitignore
├── LICENSE                      # MIT
└── README.md                    # This file
```

### Self-Contained

SPLUNK-BOT is completely independent:

- **Own index**: `splunk_bot` — no dependency on other apps or indexes
- **Own sourcetype**: `splunkbot:audit:finding` with JSON auto-extraction
- **Own file monitor**: Watches `/opt/splunk/var/log/splunk_bot/` for audit JSON
- **Own dashboard**: Dashboard Studio v2 with absolute layout and SVG background

## The Dashboard

The dashboard uses a retro CRT terminal aesthetic:

- **Background**: SVG with scanline overlay, phosphor glow gradient, bezel frame
- **Colors**: Green phosphor (`#00ff41`) primary, with severity-specific accent colors
- **Typography**: Monospace-influenced titles (`HEALTH_SCORE`, `SYS_STATUS`, `DOMAIN_SCORES`)
- **Layout**: Absolute positioning for pixel-perfect placement, 1440x1900 with auto-scale
- **Cards**: Semi-transparent dark panels with green terminal-style borders

### Panels

| Panel | Type | Description |
|-------|------|-------------|
| HEALTH_SCORE | Single value | Overall weighted score (0-100) |
| SYS_STATUS | Single value | CRITICAL / WARNING / HEALTHY |
| CRITICAL / WARNING / INFO / PASS | Single values | Severity counts |
| DOMAIN_SCORES | Column chart | Per-domain scores (max 100) |
| SCORE_HISTORY | Line chart | Score trend over time |
| CRITICAL FINDINGS | Table | Red-bordered critical issues |
| WARNING FINDINGS | Table | Amber-bordered warnings |
| INFO FINDINGS | Table | Cyan-bordered informational |
| OK FINDINGS | Table | Green-bordered passing checks |
| TERMINAL_LOG | Table | Last 5 raw audit events |

## Installation

### Prerequisites

- Splunk Enterprise 10.x (tested on 10.2.1)
- SSH access to the Splunk host
- Admin credentials for the Splunk REST API

### Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/DaveBergman/splunk-bot.git
cd splunk-bot

# 2. Set up credentials
cp .env.example .env
# Edit .env with your Splunk host, SSH key, and admin password

# 3. Source credentials
source .env

# 4. Deploy to Splunk
./deploy/deploy_am06.sh

# 5. (Optional) Seed sample data for testing
./deploy/seed_sample_data.sh
```

The dashboard will be available at:
```
http://<SPLUNK_HOST>:8000/en-GB/app/splunk_bot/bot_audit
```

### Manual Installation

If you prefer to install manually:

1. Copy `splunk_app/splunk_bot/` to `$SPLUNK_HOME/etc/apps/splunk_bot/`
2. Create the audit log directory: `mkdir -p $SPLUNK_HOME/var/log/splunk_bot/`
3. Restart Splunk: `$SPLUNK_HOME/bin/splunk restart`
4. Deploy the dashboard via REST API (file copy does NOT work for Studio v2):

```bash
curl -s -k -u admin:$SPLUNK_PASS \
  -X POST "https://127.0.0.1:8089/servicesNS/admin/splunk_bot/data/ui/views" \
  -d name=bot_audit \
  --data-urlencode "eai:data@splunk_app/splunk_bot/default/data/ui/views/bot_audit.xml"
```

## Data Format

SPLUNK-BOT expects JSON events in `/opt/splunk/var/log/splunk_bot/audit_*.json`, one event per line.

### Event Types

**Summary** (one per audit run):
```json
{
  "audit_time": "2026-04-03T16:00:00+0100",
  "audit_id": "2026-04-03",
  "host": "am06",
  "splunk_version": "10.2.1",
  "event_type": "summary",
  "overall_score": 63,
  "overall_status": "WARNING",
  "critical_count": 2,
  "warning_count": 5,
  "info_count": 8,
  "ok_count": 20,
  "domains_audited": 8
}
```

**Domain Score** (one per domain per audit):
```json
{
  "audit_time": "2026-04-03T16:00:00+0100",
  "audit_id": "2026-04-03",
  "event_type": "domain_score",
  "domain": "system_health",
  "domain_label": "System Health",
  "domain_score": 70,
  "domain_weight": 15,
  "weighted_score": 10.5
}
```

**Finding** (one per check per audit):
```json
{
  "audit_time": "2026-04-03T16:00:00+0100",
  "audit_id": "2026-04-03",
  "event_type": "finding",
  "domain": "system_health",
  "domain_label": "System Health",
  "check": "disk_space",
  "check_label": "Disk Space",
  "result": "78% used",
  "severity": "WARNING",
  "detail": "$SPLUNK_HOME partition >75% full",
  "score": 40
}
```

## Deployment Notes

### Dashboard Studio v2 Requires REST API

Dashboard Studio v2 dashboards **must** be deployed via the Splunk REST API. Copying XML files to `default/data/ui/views/` does not set the internal metadata (`isDashboard: True`, `version: 2`) that the frontend requires. Symptoms of file-based deployment:

- Dashboard renders blank
- URL gets `?tab=layout_1` appended (classic-mode fallback)
- Title bar shows "undefined"

The deploy script handles this automatically.

### Absolute Layout

The dashboard uses absolute layout (not grid) to avoid the `min-height: 0px` CSS collapse that occurs with grid layout on some Splunk Enterprise 10.x builds. All panels have explicit `x, y, w, h` coordinates.

### Splunk Restart Timing

After `splunk restart`, the web server and management port may take 30-60 seconds to become ready. The deploy script includes appropriate waits.

## Running an Audit

SPLUNK-BOT is designed to work with the `splunk-performance-audit` AI skill. To run an audit:

1. Open Cursor IDE
2. Say: "Run the splunk-performance-audit skill on AM06 and update the splunk-bot audit dashboard"
3. The skill will SSH to your Splunk host, run all checks, and write findings to the `splunk_bot` index

Or click the **> RERUN AUDIT_** link on the dashboard itself.

## Contributing

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Test with `deploy/seed_sample_data.sh`
5. Submit a PR

## License

MIT — see [LICENSE](LICENSE).

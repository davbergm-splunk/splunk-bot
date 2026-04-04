<p align="center">
  <img src="splunk-bot-icon.png" width="96" alt="SPLUNK-BOT"/>
</p>

<h1 align="center">SPLUNK-BOT User Guide</h1>

<p align="center">Complete reference for installing, configuring, running, and extending SPLUNK-BOT — a retro terminal-themed platform health audit for Splunk Enterprise.</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Installation](#installation)
   - [Quick Start](#quick-start)
   - [Manual Installation](#manual-installation)
   - [QEMU VM Setup (Apple Silicon)](#qemu-vm-setup-apple-silicon)
4. [Configuration](#configuration)
   - [Environment Variables (.env)](#environment-variables-env)
   - [Splunk Credentials for In-App Audit](#splunk-credentials-for-in-app-audit)
   - [Scheduled Audits](#scheduled-audits)
   - [Dashboard Caching](#dashboard-caching)
5. [Running an Audit](#running-an-audit)
   - [Method 1: CLI (splunk-bot-audit.sh)](#method-1-cli-splunk-bot-auditsh)
   - [Method 2: In-Splunk (| runaudit)](#method-2-in-splunk--runaudit)
   - [Method 3: Dashboard Rerun Link](#method-3-dashboard-rerun-link)
   - [Method 4: Cursor IDE Skill](#method-4-cursor-ide-skill)
6. [The Audit Domains](#the-audit-domains)
   - [Domain 1: System Health](#domain-1-system-health)
   - [Domain 2: Licensing](#domain-2-licensing)
   - [Domain 3: Clustering](#domain-3-clustering)
   - [Domain 4: Apps](#domain-4-apps)
   - [Domain 5: Usage](#domain-5-usage)
   - [Domain 6: Search Performance](#domain-6-search-performance)
   - [Domain 7: Dashboards](#domain-7-dashboards)
   - [Domain 8: Indexes](#domain-8-indexes)
7. [Scoring System](#scoring-system)
8. [The Dashboard](#the-dashboard)
   - [Panel Reference](#panel-reference)
   - [Fix Prompt Generator](#fix-prompt-generator)
9. [Data Model](#data-model)
   - [Index and Sourcetype](#index-and-sourcetype)
   - [Event Types](#event-types)
10. [VM Management (splunk-vm.sh)](#vm-management-splunk-vmsh)
11. [Deployment](#deployment)
    - [Manual Deployment](#manual-deployment)
    - [deploy_am06.sh](#deploy_am06sh)
    - [GitHub Actions CI/CD](#github-actions-cicd)
12. [Troubleshooting](#troubleshooting)
13. [File Reference](#file-reference)
14. [License](#license)

---

## Overview

SPLUNK-BOT is a self-contained Splunk app that audits your Splunk Enterprise instance across **8 domains**, scores each finding on a 0–100 scale, and displays results in a retro CRT green-phosphor dashboard built with Dashboard Studio v2.

There are two audit engines:

| Engine | File | Runs Where | How |
|--------|------|-----------|-----|
| **CLI (Bash)** | `bin/splunk-bot-audit.sh` | Your workstation | SSH to Splunk host, runs CLI commands |
| **In-Splunk (Python)** | `splunk_app/splunk_bot/bin/audit_runner.py` | Inside Splunk | REST API + local OS commands |

Both produce identical JSON events in the `splunk_bot` index, consumed by the same dashboard.

---

## Requirements

| Component | Minimum |
|-----------|---------|
| Splunk Enterprise | 9.x or 10.x (tested on 10.2.2) |
| Python | 3.9+ (Splunk embedded or system) |
| Bash | 4.0+ (for CLI audit) |
| SSH | Key-based or password-based access to the Splunk host |
| `sshpass` | Only if using password-based SSH (install via `brew install hudochenkov/sshpass/sshpass` on macOS) |
| `jq` | Optional — for pretty-printed CLI output |
| Disk | ~10 MB for the app; ~1 MB per audit run in the `splunk_bot` index |

---

## Installation

### Quick Start

```bash
# 1. Clone
git clone https://github.com/davbergm-splunk/splunk-bot.git
cd splunk-bot

# 2. Configure credentials
cp .env.example .env
# Edit .env — set SSH_HOST, SSH_USER, SSH_KEY, SPLUNK_PASS at minimum

# 3. Source them
source .env

# 4. Deploy the Splunk app
./deploy/deploy_am06.sh

# 5. (Optional) Seed sample data for a demo
./deploy/seed_sample_data.sh
```

Open the dashboard: `http://<SPLUNK_HOST>:8000/en-GB/app/splunk_bot/bot_audit`

### Manual Installation

1. **Copy the app** to your Splunk instance:

```bash
scp -r splunk_app/splunk_bot/ user@splunk-host:/opt/splunk/etc/apps/splunk_bot/
```

2. **Create the audit log directory**:

```bash
ssh user@splunk-host "mkdir -p /opt/splunk/var/log/splunk_bot/"
```

3. **Restart Splunk**:

```bash
ssh user@splunk-host "/opt/splunk/bin/splunk restart"
```

4. **Deploy the dashboard via REST API** (required for Studio v2):

```bash
ssh user@splunk-host "curl -sk -u admin:\$SPLUNK_PASS \
  -X POST 'https://127.0.0.1:8089/servicesNS/admin/splunk_bot/data/ui/views' \
  -d name=bot_audit \
  --data-urlencode 'eai:data@/opt/splunk/etc/apps/splunk_bot/default/data/ui/views/bot_audit.xml'"
```

> **Why REST?** Dashboard Studio v2 requires internal metadata (`isDashboard: True`, `version: 2`) that only the REST API sets. File-only deployment renders a blank page.

5. **Set up in-Splunk audit credentials** (for `| runaudit`):

```bash
ssh user@splunk-host "cat > /opt/splunk/etc/apps/splunk_bot/local/audit_creds.conf << 'EOF'
[auth]
username = admin
password = your_admin_password
EOF"
```

### QEMU VM Setup (Apple Silicon)

Splunk 10.x requires AVX instructions not available natively on Apple Silicon. Run it in an x86_64 Linux VM:

```bash
# Install QEMU
brew install qemu cdrtools

# Download Ubuntu cloud image
cd ~/splunk-vm
curl -LO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
qemu-img create -f qcow2 -b noble-server-cloudimg-amd64.img -F qcow2 splunk-vm.qcow2 40G

# Boot with AVX-capable CPU emulation
qemu-system-x86_64 \
  -machine q35 -cpu Haswell-v4 -smp 2 -m 4G \
  -drive file=splunk-vm.qcow2,format=qcow2,if=virtio \
  -nic user,hostfwd=tcp::2222-:22,hostfwd=tcp::8000-:8000,hostfwd=tcp::8089-:8089 \
  -nographic
```

After VM setup, use `bin/splunk-vm.sh` to manage it (see [VM Management](#vm-management-splunk-vmsh)).

---

## Configuration

### Environment Variables (.env)

Create `.env` in the repo root (never commit this file). Template at `.env.example`:

```bash
# === Key-based SSH (default) ===
SSH_KEY=~/.ssh/id_ed25519
SSH_USER=dave
SSH_HOST=192.168.1.114
SSH_PORT=22
SPLUNK_HOME_REMOTE=/opt/splunk
SPLUNK_USER=admin
SPLUNK_PASS=changeme

# === Password-based SSH (QEMU VM mode) ===
# SSH_PASS=splunk
# SSH_USER=splunk
# SSH_HOST=localhost
# SSH_PORT=2222
# SPLUNK_PASS=changeme123
```

| Variable | Description | Default |
|----------|-------------|---------|
| `SSH_KEY` | Path to SSH private key | `~/.ssh/id_ed25519` |
| `SSH_USER` | SSH username | `dave` |
| `SSH_HOST` | Splunk host IP or hostname | `192.168.1.114` |
| `SSH_PORT` | SSH port | `22` |
| `SSH_PASS` | SSH password (enables sshpass mode) | *(empty = key auth)* |
| `SPLUNK_HOME_REMOTE` | Remote `$SPLUNK_HOME` path | `/opt/splunk` |
| `SPLUNK_USER` | Splunk admin username | `admin` |
| `SPLUNK_PASS` | Splunk admin password | *(required)* |

### Splunk Credentials for In-App Audit

The `| runaudit` search command needs admin REST access. Create a local credentials file on the Splunk host:

```
$SPLUNK_HOME/etc/apps/splunk_bot/local/audit_creds.conf
```

```ini
[auth]
username = admin
password = your_admin_password
```

This file is read by `runaudit.py` at execution time. It is not shipped with the app and should be protected with appropriate file permissions.

### Scheduled Audits

Three saved searches are included in `savedsearches.conf`:

| Saved Search | Schedule | Default State |
|-------------|----------|---------------|
| **SPLUNK-BOT Run Audit** | On demand | Enabled |
| **SPLUNK-BOT Scheduled Audit** | Daily at 06:00 | Disabled |
| **SPLUNK-BOT Dashboard Cache** | Every 10 minutes | Enabled |

To enable the daily scheduled audit:

```
Settings > Searches, reports, and alerts > SPLUNK-BOT Scheduled Audit > Edit > Enable
```

Or via CLI:

```bash
splunk edit saved-search "SPLUNK-BOT Scheduled Audit" -app splunk_bot -disabled 0 -auth admin:pass
```

### Dashboard Caching

The dashboard uses a pre-computing saved search (`SPLUNK-BOT Dashboard Cache`) that runs every 10 minutes and caches all audit data. Each dashboard panel reads from this cache via `| savedsearch "SPLUNK-BOT Dashboard Cache"` with a 5-minute browser-side refresh delay.

This architecture means:
- The heavy index scan runs **once** every 10 minutes in the background
- Dashboard loads read a **pre-computed result set** and apply lightweight in-memory filters
- The browser does not re-dispatch searches for 5 minutes after each load

To adjust the cache interval, edit the `cron_schedule` in `savedsearches.conf`:

```ini
[SPLUNK-BOT Dashboard Cache]
cron_schedule = */10 * * * *   # Change to */5 for more frequent updates
dispatch.ttl = 900             # Results cached for 15 minutes
```

---

## Running an Audit

### Method 1: CLI (splunk-bot-audit.sh)

The standalone bash script connects to your Splunk host via SSH, runs all 8 domain checks, and writes results to both the `splunk_bot` index and a local markdown report.

```bash
source .env
./bin/splunk-bot-audit.sh
```

#### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--host HOST` | Splunk host | `$SSH_HOST` / `192.168.1.114` |
| `--port PORT` | SSH port | `$SSH_PORT` / `22` |
| `--user USER` | SSH user | `$SSH_USER` / `dave` |
| `--key PATH` | SSH private key | `$SSH_KEY` / `~/.ssh/id_ed25519` |
| `--ssh-pass PASS` | SSH password (uses sshpass) | `$SSH_PASS` / *(empty)* |
| `--splunk-user USER` | Splunk admin user | `$SPLUNK_USER` / `admin` |
| `--splunk-pass PASS` | Splunk admin password | `$SPLUNK_PASS` |
| `--dry-run` | Print commands without executing | Off |
| `--help` | Show usage | — |

#### Examples

```bash
# Key-based SSH to a remote host
./bin/splunk-bot-audit.sh --host 192.168.1.114 --splunk-pass changeme

# Password-based SSH to a QEMU VM
./bin/splunk-bot-audit.sh --host localhost --port 2222 --ssh-pass splunk --splunk-pass changeme123

# Dry run — see what commands would execute
./bin/splunk-bot-audit.sh --dry-run
```

#### Output

The script produces three outputs:

1. **Terminal** — colour-coded summary with domain headers and severity-tagged findings
2. **Splunk index** — JSON events written to `/opt/splunk/var/log/splunk_bot/audit_<date>.json` (automatically ingested by the file monitor)
3. **Markdown report** — saved to `reports/SPLUNK_BOT_AUDIT_<date>.md` locally

### Method 2: In-Splunk (| runaudit)

Run the audit directly from the Splunk search bar:

```spl
| runaudit
```

This executes the Python audit runner inside Splunk and returns a summary row:

| status | score | findings | critical | warning | info | ok | output_file |
|--------|-------|----------|----------|---------|------|----|-------------|
| WARNING | 88 | 17 | 0 | 2 | 3 | 12 | /opt/splunk/var/log/splunk_bot/audit_2026-04-03.json |

The full JSON events are written to disk and automatically ingested by the file monitor into the `splunk_bot` index.

**Prerequisites**: The `audit_creds.conf` file must exist on the Splunk host (see [Splunk Credentials for In-App Audit](#splunk-credentials-for-in-app-audit)).

### Method 3: Dashboard Rerun Link

The dashboard includes a **> RUN_AUDIT_** link in the header and a **> RUN_AUDIT_NOW** section at the bottom. Clicking either opens a Splunk search window with `| runaudit` pre-filled. Run it, wait for completion, then refresh the dashboard.

### Method 4: Cursor IDE Skill

If you use Cursor IDE with the `splunk-performance-audit` skill:

1. Open Cursor
2. Say: *"Run the splunk-performance-audit skill"*
3. The skill SSHes to your Splunk host, runs all checks, and writes findings to the `splunk_bot` index

---

## The Audit Domains

Each domain receives a score from 0–100 and a configurable weight that determines its contribution to the overall health score.

### Domain 1: System Health

**Weight: 15%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Splunk Version | Installed version string | Always OK (informational) |
| CPU/RAM | Core count, total/available memory | CRITICAL <2 GB avail, WARNING <4 GB |
| Disk Space | `$SPLUNK_HOME` partition usage | CRITICAL >95%, WARNING >85%/>75% |
| Dispatch Dir | Size of `var/run/splunk/dispatch/` | CRITICAL >50 GB, WARNING >10 GB, INFO >5 GB |
| KV Store | kvstore-status | CRITICAL if down/degraded, OK if ready |

### Domain 2: Licensing

**Weight: 10%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| License Type | Enterprise / Trial / Free | OK = Enterprise, WARNING = Trial, INFO = Free |
| Daily Usage | GB/day vs quota | CRITICAL >95%, WARNING >80% |
| Violations | Count in last 30 days | CRITICAL >5 (block imminent), WARNING >0 |

### Domain 3: Clustering

**Weight: 10%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Cluster Mode | Enabled/disabled, replication factor | OK in all normal configurations |

### Domain 4: Apps

**Weight: 10%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| App Count | Total installed apps | INFO >50 |
| Disabled Apps | Non-bundled disabled apps | INFO if any found |
| Config Validation | `btool check --debug` errors | WARNING if errors/missing specs found |

### Domain 5: Usage

**Weight: 10%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Scheduled Searches | Enabled scheduled search count | WARNING >100, INFO >50 |
| Skipped Searches | Scheduler skip count in 24h | WARNING >50 skips |

### Domain 6: Search Performance

**Weight: 20%** (highest weight)

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Long Running Searches | Searches >600s in past 7 days | CRITICAL >10, WARNING >0 |
| Real-Time Searches | Currently active RT searches | CRITICAL >10, WARNING >3, INFO >0 |
| Search Concurrency | Active jobs vs max limit | CRITICAL >90%, WARNING >70% |
| Wildcard Searches | Saved searches using `index=*` | CRITICAL >3, WARNING >0 |
| Dispatch Directory | Size of search artifacts | CRITICAL >10 GB, WARNING >5 GB |

### Domain 7: Dashboards

**Weight: 10%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Studio v2 Ratio | Proportion of Studio v2 vs Classic XML | OK >50%, INFO otherwise |

### Domain 8: Indexes

**Weight: 15%**

| Check | What It Measures | Thresholds |
|-------|-----------------|------------|
| Total Index Size | Aggregate size across active indexes | Always OK (informational) |
| Dead Indexes | Enabled indexes with 0 events | INFO if any found |
| Retention Policy | Indexes without explicit `frozenTimePeriodInSecs` | INFO if any found |

---

## Scoring System

### Finding Scores

Each individual check produces a score from 0–100:

| Score Range | Typical Severity | Meaning |
|------------|------------------|---------|
| 90–100 | OK | Healthy, within thresholds |
| 60–89 | INFO | Suboptimal but functional |
| 30–59 | WARNING | Degraded, fix within a week |
| 0–29 | CRITICAL | Service at risk, fix immediately |

### Domain Scores

Each domain score is the **average** of its individual finding scores.

### Overall Health Score

The overall score is a **weighted sum** of domain scores:

```
Overall = Σ (domain_score × domain_weight / 100)
```

| Domain | Weight |
|--------|--------|
| System Health | 15% |
| Licensing | 10% |
| Clustering | 10% |
| Apps | 10% |
| Usage | 10% |
| Search Performance | 20% |
| Dashboards | 10% |
| Indexes | 15% |
| **Total** | **100%** |

### Overall Status

| Status | Condition |
|--------|-----------|
| CRITICAL | Any CRITICAL findings |
| WARNING | Any WARNING findings (no CRITICAL) |
| HEALTHY | All findings OK or INFO |

---

## The Dashboard

The dashboard is a Dashboard Studio v2 absolute-layout design with a retro CRT terminal aesthetic:

- **Background**: SVG with scanline overlay, phosphor glow gradient, and bezel frame
- **Colour palette**: Green phosphor `#00ff41`, red `#ff3b30`, amber `#ffcc00`, cyan `#00bfff`
- **Canvas**: 1440 x 2350 pixels with auto-scale
- **Theme**: Dark

### Panel Reference

| Panel | Visualization | Data Source |
|-------|-------------|-------------|
| **HEALTH_SCORE** | Single value (60pt green) | Latest `overall_score` from summary |
| **SYS_STATUS** | Single value (40pt green) | Latest `overall_status` from summary |
| **CRITICAL** | Single value (36pt red) | `critical_count` |
| **WARNING** | Single value (36pt amber) | `warning_count` |
| **INFO** | Single value (36pt cyan) | `info_count` |
| **PASS** | Single value (36pt green) | `ok_count` |
| **DOMAIN_SCORES** | Column chart | Per-domain scores, Y-axis max 100 |
| **SCORE_HISTORY** | Line chart | Score trend over time (daily) |
| **CRITICAL FINDINGS** | Table (red border) | Findings where severity=CRITICAL |
| **WARNING FINDINGS** | Table (amber border) | Findings where severity=WARNING |
| **INFO FINDINGS** | Table (cyan border) | Findings where severity=INFO |
| **OK FINDINGS** | Table (green border) | Findings where severity=OK |
| **TERMINAL_LOG** | Table | Last 5 audit events, formatted as terminal output |
| **LAST_AUDIT** | Single value | Timestamp, score, and status of last audit run |
| **FIX_PROMPT** | Table (amber border) | Auto-generated prompt from non-OK findings |

### Fix Prompt Generator

The bottom panel automatically generates a copy-paste prompt from all non-OK findings. It includes severity, check name, result, and the `fix_prompt` field from each finding. Paste this into Cursor, ChatGPT, or any AI assistant to get targeted fix commands for your specific environment.

---

## Data Model

### Index and Sourcetype

| Setting | Value |
|---------|-------|
| Index | `splunk_bot` |
| Sourcetype | `splunkbot:audit:finding` |
| Parsing | `KV_MODE = json` |
| Retention | 180 days (`frozenTimePeriodInSecs = 15552000`) |
| Line breaking | One JSON object per line |

Data is ingested via a file monitor on `/opt/splunk/var/log/splunk_bot/`.

### Event Types

Every audit run produces three types of JSON events:

**1. Summary** (1 per audit)

```json
{
  "event_type": "summary",
  "audit_time": "2026-04-03T16:00:00+0000",
  "audit_id": "2026-04-03",
  "host": "splunk-vm",
  "splunk_version": "10.2.2",
  "overall_score": 88,
  "overall_status": "WARNING",
  "critical_count": 0,
  "warning_count": 2,
  "info_count": 3,
  "ok_count": 12,
  "domains_audited": 8
}
```

**2. Domain Score** (8 per audit, one per domain)

```json
{
  "event_type": "domain_score",
  "domain": "system_health",
  "domain_label": "System Health",
  "domain_score": 92,
  "domain_weight": 15,
  "weighted_score": 13.8
}
```

**3. Finding** (one per check, typically 15–25 per audit)

```json
{
  "event_type": "finding",
  "domain": "system_health",
  "domain_label": "System Health",
  "check": "disk_space",
  "check_label": "Disk Space",
  "result": "42% used",
  "severity": "OK",
  "detail": "",
  "score": 100,
  "fix_prompt": ""
}
```

The `fix_prompt` field (Python engine only) contains a human-readable remediation hint used by the Fix Prompt Generator panel.

---

## VM Management (splunk-vm.sh)

The `bin/splunk-vm.sh` script manages the QEMU VM lifecycle for Apple Silicon users.

### Commands

```bash
./bin/splunk-vm.sh start        # Boot the VM, wait for Splunk
./bin/splunk-vm.sh stop         # Graceful shutdown
./bin/splunk-vm.sh status       # Show VM, SSH, and Splunk health
./bin/splunk-vm.sh open         # Auto-login and open dashboard in browser
./bin/splunk-vm.sh open /path   # Open a specific Splunk path
./bin/splunk-vm.sh ssh          # Interactive SSH session to the VM
./bin/splunk-vm.sh restart      # Restart Splunk inside the VM
```

### Auto-Login (`open`)

The `open` command:

1. Authenticates against the Splunk REST API to get a session token
2. Starts a one-shot local HTTP server on port 9876
3. Opens your browser to `http://127.0.0.1:9876/` which 302-redirects to Splunk with the session cookie set
4. You land directly on the dashboard — no login page

### SSH Alias

An SSH config entry for the VM is recommended:

```
# ~/.ssh/config
Host splunk-vm
    HostName localhost
    Port 2222
    User splunk
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
```

Then: `ssh splunk-vm`

### Environment Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `VM_DIR` | `~/splunk-vm` | Directory containing VM image |
| `VM_IMAGE` | `$VM_DIR/splunk-vm.qcow2` | QCOW2 disk image path |
| `VM_PIDFILE` | `$VM_DIR/qemu.pid` | QEMU PID file |
| `SSH_PORT` | `2222` | Forwarded SSH port |
| `SPLUNK_WEB_PORT` | `8000` | Forwarded Splunk web port |
| `SPLUNK_MGMT_PORT` | `8089` | Forwarded Splunk mgmt port |

---

## Deployment

### Manual Deployment

1. Copy `splunk_app/splunk_bot/` to `$SPLUNK_HOME/etc/apps/splunk_bot/` on the target
2. Deploy dashboard via REST API (see [Manual Installation](#manual-installation))
3. Create `audit_creds.conf` for in-app audit
4. Restart Splunk

### deploy_am06.sh

The deployment script automates the full process:

```bash
source .env
./deploy/deploy_am06.sh
```

Steps:
1. `rsync` app files (excluding dashboard views)
2. Ensure views directory exists
3. Create audit log directory
4. Deploy dashboard via REST API (create or update)
5. Restart Splunk and verify

### GitHub Actions CI/CD

Three workflows are included:

| Workflow | Trigger | What It Does |
|----------|---------|-------------|
| **Validate** (`validate.yml`) | Push/PR to `main` | Checks required files exist, validates XML parsing, verifies script permissions |
| **Deploy** (`deploy.yml`) | Manual dispatch | Deploys to AM06 via self-hosted runner with rsync + REST |
| **Mirror** (`mirror.yml`) | Push to `main` | Force-pushes to DaveBergman mirror repo |

---

## Troubleshooting

### Dashboard is blank

**Cause**: Dashboard was deployed via file copy instead of REST API.

**Fix**: Deploy via REST:

```bash
curl -sk -u admin:$SPLUNK_PASS \
  -X POST "https://127.0.0.1:8089/servicesNS/admin/splunk_bot/data/ui/views/bot_audit" \
  --data-urlencode "eai:data@bot_audit.xml"
```

### Dashboard shows "no results"

**Cause**: No audit data in the `splunk_bot` index, or the cached saved search hasn't run yet.

**Fix**:
1. Run an audit: `| runaudit` from the search bar, or `./bin/splunk-bot-audit.sh` from CLI
2. Wait 60 seconds for the file monitor to ingest the data
3. Verify data exists: `index=splunk_bot | head 5`
4. Manually dispatch the cache: `splunk dispatch "SPLUNK-BOT Dashboard Cache" -auth admin:pass`

### `| runaudit` returns "Could not authenticate"

**Cause**: Missing or incorrect `audit_creds.conf`.

**Fix**: Create the credentials file on the Splunk host:

```bash
cat > $SPLUNK_HOME/etc/apps/splunk_bot/local/audit_creds.conf << 'EOF'
[auth]
username = admin
password = your_password
EOF
chmod 600 $SPLUNK_HOME/etc/apps/splunk_bot/local/audit_creds.conf
```

### CLI audit exits silently after first finding

**Cause**: Old version of the script with `set -euo pipefail` (the `-e` flag exits on any non-zero return code from subcommands).

**Fix**: Pull the latest version. The script now uses `set -uo pipefail` (no `-e`).

### SSH connection refused on port 2222

**Cause**: QEMU VM is not running.

**Fix**: Start it with `./bin/splunk-vm.sh start` or boot manually.

### Splunk "PID file unreadable"

**Cause**: File ownership mismatch after a hard kill or restart.

**Fix**:

```bash
ssh splunk-vm "sudo chown -R splunk:splunk /opt/splunk/var/run/splunk/"
```

### Dashboard slow to load

**Cause**: Emulated CPU (QEMU) or cache not primed.

**Fix**:
1. Ensure the `SPLUNK-BOT Dashboard Cache` saved search is enabled and running
2. Manually dispatch it: `splunk dispatch "SPLUNK-BOT Dashboard Cache" -auth admin:pass`
3. All dashboard panels read from the cache — subsequent loads will be fast

---

## File Reference

```
splunk-bot/
├── .env.example                         # Credential template (copy to .env)
├── .github/workflows/
│   ├── deploy.yml                       # Manual deploy to AM06 (self-hosted runner)
│   ├── mirror.yml                       # Auto-mirror to DaveBergman org
│   └── validate.yml                     # CI: file checks + XML validation
├── bin/
│   ├── splunk-bot-audit.sh              # Standalone CLI audit runner
│   └── splunk-vm.sh                     # QEMU VM management script
├── deploy/
│   ├── deploy_am06.sh                   # Full deployment script
│   └── seed_sample_data.sh              # Seed test data for demo
├── docs/
│   ├── splunk-bot-icon.png              # App icon (256px, for README)
│   └── USER_GUIDE.md                    # This file
├── reports/                             # Generated markdown reports (gitignored)
├── splunk_app/splunk_bot/
│   ├── appserver/static/
│   │   ├── appIcon.png                  # App icon 36x36
│   │   ├── appIcon.svg                  # App icon source SVG
│   │   ├── appIcon_2x.png              # App icon 72x72 (HiDPI)
│   │   └── terminal_bg.svg             # Dashboard CRT background
│   ├── bin/
│   │   ├── audit_runner.py              # In-Splunk audit engine (Python)
│   │   └── runaudit.py                  # Custom search command wrapper
│   ├── default/
│   │   ├── app.conf                     # App identity and metadata
│   │   ├── commands.conf                # Registers | runaudit command
│   │   ├── data/ui/
│   │   │   ├── nav/default.xml          # Navigation menu
│   │   │   └── views/bot_audit.xml      # Dashboard Studio v2 definition
│   │   ├── indexes.conf                 # splunk_bot index (180-day retention)
│   │   ├── inputs.conf                  # File monitor for audit JSON
│   │   ├── props.conf                   # JSON extraction rules
│   │   └── savedsearches.conf           # Run/schedule/cache saved searches
│   └── metadata/default.meta            # App permissions (export to system)
├── LICENSE                              # MIT
└── README.md                            # Project overview
```

---

## License

MIT — see [LICENSE](../LICENSE).

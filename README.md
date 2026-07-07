# DNS Exposure Monitor

> **IITM Project** — Python-based monitoring system that scans a list of URLs, detects raw IP address exposure (instead of proper DNS hostnames), and delivers WhatsApp alerts via Twilio through a full issue-lifecycle state machine.

---

## Table of Contents
1. [Project Structure](#project-structure)
2. [How It Works](#how-it-works)
3. [Setup](#setup)
4. [Twilio WhatsApp Sandbox](#twilio-whatsapp-sandbox)
5. [Running the Monitor](#running-the-monitor)
6. [Configuration Reference](#configuration-reference)
7. [State Machine](#state-machine)
8. [Logs & Audit Trail](#logs--audit-trail)

---

## Project Structure

```
dns-exposure-monitor/
├── scheduler.py        # Main entry point & APScheduler loop
├── scanner.py          # HTTP checking + IP detection logic
├── db.py               # SQLite schema & state-transition helpers
├── notifier.py         # Twilio WhatsApp alert templates
├── config.py           # All config values (env-var driven)
├── iitm_urls.txt       # 291 IITM subdomains to monitor
├── requirements.txt
├── .env.example        # Template — copy to .env and fill in
└── README.md
```

---

## How It Works

1. **Load URLs** — reads `iitm_urls.txt` (`.txt` or `.csv` supported).
2. **HTTP scan** — follows all redirects, captures the *final* URL (`response.url`) with timeout + retry logic.
3. **IP detection** — parses the final host; uses Python's `ipaddress` module to detect raw IPv4/IPv6 addresses.
4. **State transitions** — updates a local SQLite database (`dns_monitor.db`) per the lifecycle below.
5. **WhatsApp alerts** — sends Twilio WhatsApp messages for detection, escalation, and resolution events.
6. **Scheduled repeat** — APScheduler re-runs the full scan every N hours (default: 6).

---

## Setup

### 1. Clone / open the project directory

```powershell
cd "d:\IITM\dns prj"
```

### 2. Create a virtual environment (recommended)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

```powershell
Copy-Item .env.example .env
notepad .env
```

Fill in your real values (see [Configuration Reference](#configuration-reference)).

---

## Twilio WhatsApp Sandbox

The free Twilio Sandbox lets you send WhatsApp messages without a dedicated number.

### Steps

1. Log in at <https://console.twilio.com>.
2. Go to **Messaging → Try it out → Send a WhatsApp message**.
3. Follow the on-screen instructions to **join the sandbox**:
   - Send the join code (e.g. `join <word>-<word>`) from *your* WhatsApp to `+1 415 523 8886`.
4. Copy your **Account SID** and **Auth Token** from the Twilio Console dashboard.
5. Set these in your `.env`:

```ini
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
ADMIN_WHATSAPP_TO=whatsapp:+91XXXXXXXXXX   # your phone with country code
```

> **Note:** Each admin number must individually join the sandbox before they can receive messages.

---

## Running the Monitor

```powershell
# Activate venv first if not already active
.venv\Scripts\Activate.ps1

# Start the scheduler (runs an immediate scan, then repeats every 6 h)
python scheduler.py
```

To stop, press **Ctrl+C**.

### Run a single one-off scan (no scheduler)

```python
# In a Python shell or quick script
from scheduler import scan_all_urls
from db import init_db
init_db()
scan_all_urls()
```

---

## Configuration Reference

All values can be set in `.env` (or as real environment variables):

| Variable | Default | Description |
|---|---|---|
| `TWILIO_ACCOUNT_SID` | — | **Required.** Twilio Account SID |
| `TWILIO_AUTH_TOKEN` | — | **Required.** Twilio Auth Token |
| `TWILIO_WHATSAPP_FROM` | `whatsapp:+14155238886` | Sandbox sender number |
| `ADMIN_WHATSAPP_TO` | — | **Required.** Admin's WhatsApp (`whatsapp:+91...`) |
| `REQUEST_TIMEOUT` | `10` | HTTP timeout (seconds) |
| `REQUEST_RETRIES` | `3` | Retries on connection errors |
| `SCAN_INTERVAL_HOURS` | `6` | How often to run a full scan |
| `ESCALATION_RETEST_LIMIT` | `3` | Retests before escalation |
| `ESCALATION_HOURS` | `48` | Hours before time-based escalation |
| `DB_PATH` | `dns_monitor.db` | SQLite database path |
| `URL_FILE` | `iitm_urls.txt` | Input URL file |
| `LOG_FILE` | `dns_monitor.log` | Audit log file |

---

## State Machine

```
         ┌─────────────────────────────────┐
         │                                 │
         ▼                                 │ issue resolved
   ┌───────────┐   raw IP found    ┌───────────────┐
   │    OK     │ ─────────────────▶│   DETECTED    │
   └───────────┘                   └───────────────┘
                                          │
                                          │ alert sent
                                          ▼
                                   ┌───────────────┐
                                   │   NOTIFIED    │◀──────────┐
                                   └───────────────┘           │
                                          │                    │
                                          │ still raw IP       │ still raw IP
                                          ▼                    │ (loop)
                                   ┌───────────────┐           │
                                   │   RETESTED    │───────────┘
                                   └───────────────┘
                                          │
                                          │ retest_count ≥ 3 OR 48 h elapsed
                                          ▼
                                   ┌───────────────┐
                                   │   ESCALATED   │
                                   └───────────────┘
                                          │
                                          │ issue resolved
                                          ▼
                                   ┌───────────────┐
                                   │   RESOLVED    │
                                   └───────────────┘
```

**Per-URL database columns:**
- `url`, `current_status`, `first_detected_time`, `last_checked_time`, `retest_count`, `last_final_url_seen`

---

## Logs & Audit Trail

Every scan cycle and every state transition is logged to both **stdout** and `dns_monitor.log`:

```
2026-07-07T12:00:00  WARNING   scanner   RAW IP DETECTED  https://example.iitm.ac.in  →  http://203.0.113.5/  (host=203.0.113.5)
2026-07-07T12:00:00  WARNING   db        STATE TRANSITION  https://example.iitm.ac.in  OK → DETECTED
2026-07-07T12:00:00  INFO      notifier  WhatsApp alert sent  SID=SM...  to=whatsapp:+91...
```

The log file is append-only and provides a full audit trail for compliance or incident review.

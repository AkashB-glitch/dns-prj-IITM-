"""
config.py
=========
Central configuration for the DNS Exposure Monitor.
All tuneable values are read from environment variables (via .env) with
sensible defaults so the system works out-of-the-box for local testing.
"""

import os
from dotenv import load_dotenv

# Load .env file from the project root (same directory as this file)
load_dotenv()

# ---------------------------------------------------------------------------
# Twilio / WhatsApp credentials
# ---------------------------------------------------------------------------
TWILIO_ACCOUNT_SID: str = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN: str = os.getenv("TWILIO_AUTH_TOKEN", "")
# The Twilio Sandbox WhatsApp number, e.g. "whatsapp:+14155238886"
TWILIO_WHATSAPP_FROM: str = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
# Admin phone to receive alerts, e.g. "whatsapp:+919345928740"
ADMIN_WHATSAPP_TO: str = os.getenv("ADMIN_WHATSAPP_TO", "")

# Optional: Twilio Content Template SIDs (HX...).
# When set, the notifier sends a structured template message instead of freeform text.
# Leave blank to use freeform text (works on Sandbox without pre-approved templates).
TWILIO_TEMPLATE_DETECTION_SID: str = os.getenv("TWILIO_TEMPLATE_DETECTION_SID", "")
TWILIO_TEMPLATE_ESCALATION_SID: str = os.getenv("TWILIO_TEMPLATE_ESCALATION_SID", "")
TWILIO_TEMPLATE_RESOLUTION_SID: str = os.getenv("TWILIO_TEMPLATE_RESOLUTION_SID", "")

# ---------------------------------------------------------------------------
# Scanner / HTTP settings
# ---------------------------------------------------------------------------
# Seconds before an HTTP request times out
REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))

# Number of automatic retries on connection/network errors
REQUEST_RETRIES: int = int(os.getenv("REQUEST_RETRIES", "3"))

# ---------------------------------------------------------------------------
# Scheduler settings
# ---------------------------------------------------------------------------
# How often (in hours) to run a full scan of all URLs
SCAN_INTERVAL_HOURS: int = int(os.getenv("SCAN_INTERVAL_HOURS", "6"))

# ---------------------------------------------------------------------------
# Escalation / lifecycle thresholds
# ---------------------------------------------------------------------------
# Number of consecutive RETESTED cycles before escalation
ESCALATION_RETEST_LIMIT: int = int(os.getenv("ESCALATION_RETEST_LIMIT", "3"))

# Hours since first_detected_time before automatic escalation (regardless of retest_count)
ESCALATION_HOURS: int = int(os.getenv("ESCALATION_HOURS", "48"))

# ---------------------------------------------------------------------------
# Database / file paths
# ---------------------------------------------------------------------------
DB_PATH: str = os.getenv("DB_PATH", "dns_monitor.db")

# Input URL file (txt or csv, one URL per line/row)
URL_FILE: str = os.getenv("URL_FILE", "iitm_urls.txt")

# Log file path
LOG_FILE: str = os.getenv("LOG_FILE", "dns_monitor.log")

"""
notifier.py
===========
WhatsApp alert delivery via the Twilio Python SDK.

Supports two modes (auto-selected per alert):
  1. Content Template  — uses content_sid + content_variables (structured,
                         required for WhatsApp Business production numbers).
  2. Freeform text     — uses body= (works on the Twilio Sandbox without
                         pre-approved templates).

Mode is chosen automatically:
  - If TWILIO_TEMPLATE_<TYPE>_SID is set in .env → use content_sid.
  - Otherwise → fall back to a rich freeform text body.

Three alert types:
  DETECTION   – raw IP spotted for the first time.
  ESCALATION  – issue still unresolved past threshold.
  RESOLUTION  – issue fixed.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

from config import (
    ADMIN_WHATSAPP_TO,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TWILIO_WHATSAPP_FROM,
    TWILIO_TEMPLATE_DETECTION_SID,
    TWILIO_TEMPLATE_ESCALATION_SID,
    TWILIO_TEMPLATE_RESOLUTION_SID,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _get_client() -> Optional[Client]:
    """Build and return a Twilio Client, or None if credentials are missing."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        logger.error(
            "Twilio credentials missing — set TWILIO_ACCOUNT_SID and "
            "TWILIO_AUTH_TOKEN in .env"
        )
        return None
    if not ADMIN_WHATSAPP_TO:
        logger.error("ADMIN_WHATSAPP_TO is not set — cannot deliver WhatsApp alert")
        return None
    return Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def _send_freeform(client: Client, body: str) -> bool:
    """Send a plain-text freeform WhatsApp message (Sandbox compatible)."""
    message = client.messages.create(
        from_=TWILIO_WHATSAPP_FROM,
        to=ADMIN_WHATSAPP_TO,
        body=body,
    )
    logger.info(
        "WhatsApp (freeform) sent  SID=%s  preview='%s...'",
        message.sid,
        body[:60],
    )
    return True


def _send_template(
    client: Client,
    content_sid: str,
    content_variables: dict,
) -> bool:
    """
    Send a Twilio Content Template message.

    content_sid        – HX... template identifier from Twilio Console
    content_variables  – dict mapping template variable indices to values
                         e.g. {"1": "https://example.com", "2": "203.0.113.5"}
    """
    message = client.messages.create(
        from_=TWILIO_WHATSAPP_FROM,
        to=ADMIN_WHATSAPP_TO,
        content_sid=content_sid,
        content_variables=json.dumps(content_variables),
    )
    logger.info(
        "WhatsApp (template %s) sent  SID=%s",
        content_sid,
        message.sid,
    )
    return True


def _deliver(
    freeform_body: str,
    template_sid: str,
    template_vars: dict,
) -> bool:
    """
    Core delivery function.

    - Uses content_sid if template_sid is non-empty.
    - Falls back to freeform_body otherwise.
    Returns True on success, False on failure.
    """
    client = _get_client()
    if client is None:
        return False

    try:
        if template_sid:
            return _send_template(client, template_sid, template_vars)
        else:
            return _send_freeform(client, freeform_body)

    except TwilioRestException as exc:
        logger.error("Twilio API error: %s", exc)
        return False
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Unexpected notifier error: %s", exc, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Time formatting helper
# ---------------------------------------------------------------------------
def _fmt_time(iso_str: Optional[str]) -> str:
    """Format a stored ISO-8601 UTC string for human display."""
    if not iso_str:
        return "unknown time"
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso_str


# ---------------------------------------------------------------------------
# Public alert functions
# ---------------------------------------------------------------------------
def send_detection_alert(url: str, ip: str, first_detected_time: str) -> bool:
    """
    Alert type 1 — raw IP spotted for the first time.

    Freeform body:
        ⚠️ DNS Exposure Detected
        URL: {url}
        Exposed IP: {ip}
        First detected at: {time}

    Template variables (if TWILIO_TEMPLATE_DETECTION_SID is set):
        {"1": url, "2": ip, "3": formatted_time}
    """
    freeform = (
        f"⚠️ *DNS Exposure Detected*\n\n"
        f"URL: {url}\n"
        f"Exposed IP: {ip}\n"
        f"First detected at: {_fmt_time(first_detected_time)}\n\n"
        f"The endpoint is resolving to a raw IP address instead of a proper "
        f"DNS hostname. Please investigate."
    )
    template_vars = {
        "1": url,
        "2": ip,
        "3": _fmt_time(first_detected_time),
    }
    logger.warning("Sending DETECTION alert  url=%s  ip=%s", url, ip)
    return _deliver(freeform, TWILIO_TEMPLATE_DETECTION_SID, template_vars)


def send_escalation_alert(
    url: str, first_detected_time: str, retest_count: int
) -> bool:
    """
    Alert type 2 — issue unresolved past escalation threshold.

    Freeform body:
        🚨 URGENT – DNS Exposure Escalation
        ...

    Template variables (if TWILIO_TEMPLATE_ESCALATION_SID is set):
        {"1": url, "2": duration_str, "3": retest_count}
    """
    # Compute human-readable elapsed duration
    try:
        dt_first = datetime.fromisoformat(first_detected_time).replace(
            tzinfo=timezone.utc
        )
        delta = datetime.now(timezone.utc) - dt_first
        hours_elapsed = int(delta.total_seconds() // 3600)
        duration_str = f"~{hours_elapsed} hours"
    except Exception:  # pylint: disable=broad-except
        duration_str = "an extended period"

    freeform = (
        f"🚨 *URGENT – DNS Exposure Escalation*\n\n"
        f"URL: {url}\n"
        f"First detected: {_fmt_time(first_detected_time)}\n"
        f"Duration unresolved: {duration_str}\n"
        f"Retests performed: {retest_count}\n\n"
        f"{url} has remained unresolved for {duration_str}. "
        f"Please investigate immediately."
    )
    template_vars = {
        "1": url,
        "2": duration_str,
        "3": str(retest_count),
    }
    logger.critical("Sending ESCALATION alert  url=%s", url)
    return _deliver(freeform, TWILIO_TEMPLATE_ESCALATION_SID, template_vars)


def send_resolution_alert(url: str) -> bool:
    """
    Alert type 3 — issue fixed.

    Freeform body:
        ✅ DNS Exposure Resolved
        ...

    Template variables (if TWILIO_TEMPLATE_RESOLUTION_SID is set):
        {"1": url}
    """
    freeform = (
        f"✅ *DNS Exposure Resolved*\n\n"
        f"URL: {url}\n\n"
        f"{url} is now resolving correctly to a proper DNS name. "
        f"Issue has been marked RESOLVED in the monitor."
    )
    template_vars = {"1": url}
    logger.info("Sending RESOLUTION alert  url=%s", url)
    return _deliver(freeform, TWILIO_TEMPLATE_RESOLUTION_SID, template_vars)

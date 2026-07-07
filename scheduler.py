"""
scheduler.py
============
Main entry point and scheduling loop for the DNS Exposure Monitor.

Run this file directly to start continuous monitoring:

    python scheduler.py

The APScheduler library is used to fire scan_all_urls() on a fixed interval
defined by SCAN_INTERVAL_HOURS in config.py.  A single scan is also triggered
immediately on startup so you don't have to wait for the first interval.

State-machine logic (per-URL):
─────────────────────────────
OK → issue found      → DETECTED → send detection alert → NOTIFIED
NOTIFIED/RETESTED → still IP  → RETESTED (retest_count++)
RETESTED           → threshold → ESCALATED → send escalation alert
any issue state    → now OK    → RESOLVED  → send resolution alert
any state          → SSL/Conn  → skip (do not change state)
"""

import logging
import sys
import time
from datetime import datetime, timezone

from apscheduler.schedulers.blocking import BlockingScheduler

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import db
import notifier
import scanner
from config import (
    ESCALATION_HOURS,
    ESCALATION_RETEST_LIMIT,
    LOG_FILE,
    SCAN_INTERVAL_HOURS,
    URL_FILE,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
_LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_DATE_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
# Suppress noisy third-party loggers
for _noisy in ("urllib3", "requests", "twilio", "apscheduler.executors"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("scheduler")


# ---------------------------------------------------------------------------
# Core scan loop
# ---------------------------------------------------------------------------
def scan_all_urls() -> None:
    """Run a complete scan of every URL and update the database + send alerts."""
    logger.info("=" * 70)
    logger.info("SCAN CYCLE START  %s", datetime.now(timezone.utc).isoformat())
    logger.info("=" * 70)

    # Load URLs from file
    try:
        urls = scanner.load_urls(URL_FILE)
    except FileNotFoundError as exc:
        logger.error("Cannot load URL file: %s", exc)
        return

    conn = db.get_connection()

    # Ensure every URL has a row in the DB
    for url in urls:
        db.upsert_url(conn, url)

    stats = {"ok": 0, "detected": 0, "retested": 0, "escalated": 0, "resolved": 0, "errors": 0}

    for url in urls:
        result = scanner.check_url(url)
        record = db.get_url_record(conn, url)
        current_status = record["current_status"] if record else "OK"

        # ------------------------------------------------------------------
        # Network failure — skip state change, log and continue
        # ------------------------------------------------------------------
        if not result.success:
            logger.warning(
                "SKIP  %s  (error: %s)  current_status=%s",
                url,
                result.error,
                current_status,
            )
            stats["errors"] += 1
            continue

        # ------------------------------------------------------------------
        # URL resolves to a raw IP address
        # ------------------------------------------------------------------
        if result.is_raw_ip:
            if current_status == "OK":
                # First detection
                db.mark_detected(conn, url, result.final_url)
                db.mark_notified(conn, url)  # will be marked NOTIFIED after alert attempt
                sent = notifier.send_detection_alert(
                    url=url,
                    ip=result.ip_detected,
                    first_detected_time=db.get_url_record(conn, url)["first_detected_time"],
                )
                if sent:
                    logger.info("Detection alert delivered for %s", url)
                stats["detected"] += 1

            elif current_status in ("NOTIFIED", "RETESTED"):
                # Already aware — increment retest, check escalation
                db.mark_retested(conn, url, result.final_url)
                record = db.get_url_record(conn, url)  # refresh
                retest_count = record["retest_count"] if record else 0
                first_det = record["first_detected_time"] if record else None

                should_escalate = retest_count >= ESCALATION_RETEST_LIMIT

                # Also escalate if 48+ hours have elapsed since first detection
                if first_det and not should_escalate:
                    try:
                        dt_first = datetime.fromisoformat(first_det).replace(tzinfo=timezone.utc)
                        hours_elapsed = (
                            datetime.now(timezone.utc) - dt_first
                        ).total_seconds() / 3600
                        if hours_elapsed >= ESCALATION_HOURS:
                            should_escalate = True
                            logger.warning(
                                "Time-based escalation triggered for %s (%.1f h elapsed)",
                                url,
                                hours_elapsed,
                            )
                    except ValueError:
                        pass

                if should_escalate:
                    db.mark_escalated(conn, url, result.final_url)
                    notifier.send_escalation_alert(
                        url=url,
                        first_detected_time=record["first_detected_time"],
                        retest_count=retest_count,
                    )
                    stats["escalated"] += 1
                else:
                    stats["retested"] += 1

            elif current_status == "ESCALATED":
                # Issue was already escalated; just update last_checked_time / final_url
                db.mark_retested(conn, url, result.final_url)
                stats["retested"] += 1

            elif current_status == "RESOLVED":
                # Issue recurred after being resolved — treat as a fresh detection
                db.mark_detected(conn, url, result.final_url)
                db.mark_notified(conn, url)
                notifier.send_detection_alert(
                    url=url,
                    ip=result.ip_detected,
                    first_detected_time=db.get_url_record(conn, url)["first_detected_time"],
                )
                stats["detected"] += 1

        # ------------------------------------------------------------------
        # URL resolves to a proper domain
        # ------------------------------------------------------------------
        else:
            if current_status not in ("OK",):
                # Was in an issue state — now fixed
                db.mark_resolved(conn, url, result.final_url)
                notifier.send_resolution_alert(url=url)
                stats["resolved"] += 1
            else:
                db.mark_ok(conn, url, result.final_url)
                stats["ok"] += 1

    conn.close()

    logger.info(
        "SCAN CYCLE COMPLETE  ok=%d  detected=%d  retested=%d  escalated=%d  resolved=%d  errors=%d",
        stats["ok"],
        stats["detected"],
        stats["retested"],
        stats["escalated"],
        stats["resolved"],
        stats["errors"],
    )
    logger.info("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    logger.info("DNS Exposure Monitor starting up.")
    logger.info("Scan interval: every %d hour(s)", SCAN_INTERVAL_HOURS)
    logger.info("Escalation after: %d retests OR %d hours", ESCALATION_RETEST_LIMIT, ESCALATION_HOURS)

    # Initialise the database
    db.init_db()

    # Run one immediate scan before the scheduler fires
    logger.info("Running initial scan immediately...")
    scan_all_urls()

    # Schedule recurring scans
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(
        scan_all_urls,
        trigger="interval",
        hours=SCAN_INTERVAL_HOURS,
        id="dns_scan",
        name="DNS Exposure Scan",
        max_instances=1,  # Prevent overlapping runs
    )

    logger.info(
        "Next scheduled scan in %d hour(s). Press Ctrl+C to stop.",
        SCAN_INTERVAL_HOURS,
    )

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped by user.")


if __name__ == "__main__":
    main()

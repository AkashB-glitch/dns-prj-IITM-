"""
scan_new_ips.py
===============
Immediately scans the 17 new IP addresses, runs them through the full
state-machine (same logic as scheduler.py), updates the DB, sends
WhatsApp alerts if a raw-IP exposure is confirmed, and prints a result table.

Run with:
    python scan_new_ips.py
"""

import sys
import logging
from datetime import datetime, timezone

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import db
import notifier
import scanner
from config import ESCALATION_HOURS, ESCALATION_RETEST_LIMIT

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
for noisy in ("urllib3", "requests", "twilio", "apscheduler"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = logging.getLogger("scan_new_ips")

# ── IPs to scan ──────────────────────────────────────────────────────────────
NEW_IPS = [
    "https://10.24.0.123",
    "https://10.24.0.124",
    "https://10.24.0.133",
    "https://10.24.0.134",
    "https://10.24.3.144",
    "https://10.24.0.100",
    "https://10.24.0.163",
    "https://10.24.2.19",
    "https://10.24.8.102",
    "https://10.24.9.36",
    "https://10.24.9.71",
    "https://10.24.9.167",
    "https://10.24.4.222",
    "https://10.24.1.48",
    "https://10.24.6.148",
    "https://10.24.7.11",
    "https://10.21.88.232",
]

# ── State-machine helper (mirrors scheduler.py) ───────────────────────────────
def process_url(conn, url: str) -> dict:
    result = scanner.check_url(url)
    db.upsert_url(conn, url)
    record = db.get_url_record(conn, url)
    current_status = record["current_status"] if record else "OK"

    outcome = {
        "url": url,
        "final_url": result.final_url or "—",
        "host": result.host or "—",
        "is_raw_ip": result.is_raw_ip,
        "old_status": current_status,
        "new_status": current_status,
        "error": result.error,
        "success": result.success,
        "alert_sent": False,
    }

    if not result.success:
        outcome["new_status"] = current_status  # no state change on error
        return outcome

    if result.is_raw_ip:
        if current_status == "OK":
            db.mark_detected(conn, url, result.final_url)
            db.mark_notified(conn, url)
            sent = notifier.send_detection_alert(
                url=url,
                ip=result.ip_detected,
                first_detected_time=db.get_url_record(conn, url)["first_detected_time"],
            )
            outcome["alert_sent"] = sent
            outcome["new_status"] = "NOTIFIED"

        elif current_status in ("NOTIFIED", "RETESTED"):
            db.mark_retested(conn, url, result.final_url)
            record = db.get_url_record(conn, url)
            retest_count = record["retest_count"] if record else 0
            first_det = record["first_detected_time"] if record else None
            should_escalate = retest_count >= ESCALATION_RETEST_LIMIT
            if first_det and not should_escalate:
                try:
                    dt_first = datetime.fromisoformat(first_det).replace(tzinfo=timezone.utc)
                    hours_elapsed = (datetime.now(timezone.utc) - dt_first).total_seconds() / 3600
                    if hours_elapsed >= ESCALATION_HOURS:
                        should_escalate = True
                except ValueError:
                    pass
            if should_escalate:
                db.mark_escalated(conn, url, result.final_url)
                notifier.send_escalation_alert(
                    url=url,
                    first_detected_time=record["first_detected_time"],
                    retest_count=retest_count,
                )
                outcome["new_status"] = "ESCALATED"
            else:
                outcome["new_status"] = "RETESTED"

        elif current_status == "ESCALATED":
            db.mark_retested(conn, url, result.final_url)
            outcome["new_status"] = "RETESTED"

        elif current_status == "RESOLVED":
            db.mark_detected(conn, url, result.final_url)
            db.mark_notified(conn, url)
            sent = notifier.send_detection_alert(
                url=url,
                ip=result.ip_detected,
                first_detected_time=db.get_url_record(conn, url)["first_detected_time"],
            )
            outcome["alert_sent"] = sent
            outcome["new_status"] = "NOTIFIED"

    else:
        if current_status not in ("OK",):
            db.mark_resolved(conn, url, result.final_url)
            notifier.send_resolution_alert(url=url)
            outcome["new_status"] = "RESOLVED"
        else:
            db.mark_ok(conn, url, result.final_url)
            outcome["new_status"] = "OK"

    return outcome


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print()
    print("=" * 70)
    print(f"  DNS RAW-IP SCAN — {len(NEW_IPS)} NEW IPs")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    db.init_db()
    conn = db.get_connection()

    results = []
    for i, url in enumerate(NEW_IPS, 1):
        print(f"\n[{i:02d}/{len(NEW_IPS)}] Scanning {url} ...")
        outcome = process_url(conn, url)
        results.append(outcome)

        status_icon = {
            "OK":       "✅ OK",
            "NOTIFIED": "🚨 NOTIFIED",
            "DETECTED": "⚠️  DETECTED",
            "RETESTED": "🔁 RETESTED",
            "ESCALATED":"🔴 ESCALATED",
            "RESOLVED": "✅ RESOLVED",
        }.get(outcome["new_status"], outcome["new_status"])

        if not outcome["success"]:
            print(f"       Status : ❌ CONNECTION ERROR")
            print(f"       Error  : {outcome['error']}")
        else:
            print(f"       Final  : {outcome['final_url']}")
            print(f"       Host   : {outcome['host']}")
            print(f"       Status : {status_icon}")
            if outcome["is_raw_ip"]:
                print(f"       ⚠️  RAW IP EXPOSURE CONFIRMED!")
                print(f"       Alert  : {'Sent ✅' if outcome['alert_sent'] else 'Skipped/Failed'}")

    conn.close()

    # ── Summary table ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("  SCAN SUMMARY")
    print("=" * 70)
    print(f"  {'#':<4} {'IP':<25} {'STATUS':<12} {'FINAL HOST'}")
    print(f"  {'-'*4} {'-'*25} {'-'*12} {'-'*25}")
    raw_ip_count = 0
    error_count = 0
    for i, r in enumerate(results, 1):
        if not r["success"]:
            status_str = "ERROR"
            host_str = r["error"][:35] if r["error"] else "unknown"
            error_count += 1
        else:
            status_str = r["new_status"]
            host_str = r["host"]
            if r["is_raw_ip"]:
                raw_ip_count += 1
        ip_short = r["url"].replace("https://", "")
        print(f"  {i:<4} {ip_short:<25} {status_str:<12} {host_str}")

    print()
    print(f"  Total  : {len(NEW_IPS)}")
    print(f"  Errors : {error_count}  (unreachable / conn refused)")
    print(f"  Raw IP : {raw_ip_count}  {'🚨 ALERTS SENT' if raw_ip_count else '(none detected)'}")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()

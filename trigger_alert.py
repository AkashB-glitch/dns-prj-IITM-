"""
Fix: scan any URL in iitm_urls.txt that is missing from the DB,
then immediately scan https://10.24.10.208 and alert if raw IP.
"""
import db, scanner, notifier
from config import URL_FILE

db.init_db()
conn = db.get_connection()

# Load all URLs from file
with open(URL_FILE, encoding="utf-8") as f:
    file_urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

# Upsert all — adds any missing rows to DB
for url in file_urls:
    db.upsert_url(conn, url)

print(f"Synced {len(file_urls)} URLs from file to DB.")

# Now specifically scan the new IP (try both https and http)
targets = ["https://10.24.10.208", "http://10.24.10.208"]

for url in targets:
    db.upsert_url(conn, url)
    print(f"\nScanning {url} ...")
    result = scanner.check_url(url)
    print(f"  success   = {result.success}")
    print(f"  final_url = {result.final_url}")
    print(f"  host      = {result.host}")
    print(f"  is_raw_ip = {result.is_raw_ip}")
    print(f"  error     = {result.error}")

    if result.success and result.is_raw_ip:
        record = db.get_url_record(conn, url)
        if record["current_status"] == "OK":
            db.mark_detected(conn, url, result.final_url)
            record = db.get_url_record(conn, url)
            sent = notifier.send_detection_alert(url, result.ip_detected, record["first_detected_time"])
            if sent:
                db.mark_notified(conn, url)
                print(f"  -> DETECTED & WhatsApp SENT! Status = NOTIFIED")
            else:
                print(f"  -> DETECTED but WhatsApp failed.")
        else:
            print(f"  -> Already tracked (status={record['current_status']})")
        break  # found working protocol, stop trying
    elif result.success:
        db.mark_ok(conn, url, result.final_url)
        print(f"  -> Resolves to a domain — marked OK.")
        break

conn.close()

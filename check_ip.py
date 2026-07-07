import db

conn = db.get_connection()

# Check if any URL resolved to this IP
cur = conn.execute(
    "SELECT url, current_status, last_final_url_seen FROM url_status WHERE last_final_url_seen LIKE ?",
    ("%10.24.8%",)
)
rows = cur.fetchall()
print("URLs resolving to 10.24.8.x:", len(rows))
for r in rows:
    print(" -", r["url"], "->", r["last_final_url_seen"], "|", r["current_status"])

# Show all OK urls and their final URLs - look for any private IP
cur2 = conn.execute(
    "SELECT url, last_final_url_seen FROM url_status WHERE current_status='OK' ORDER BY url"
)
ok_rows = cur2.fetchall()

print("\nAll OK resolved URLs (checking for private IPs):")
private_found = []
for r in ok_rows:
    final = r["last_final_url_seen"] or ""
    # Flag any private IP ranges
    import re
    if re.search(r"https?://(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", final):
        private_found.append((r["url"], final))
        print(f"  *** PRIVATE IP: {r['url']} -> {final}")

if not private_found:
    print("  None of the 206 OK URLs redirected to a private IP.")

print(f"\nTotal OK URLs scanned: {len(ok_rows)}")
conn.close()

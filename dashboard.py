"""
dashboard.py — Flask web dashboard for DNS Exposure Monitor
Run: python dashboard.py  → opens at http://127.0.0.1:5000
"""
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import db, scanner, notifier
from config import URL_FILE
from datetime import datetime, timezone

app = Flask(__name__)
db.init_db()

# ── helpers ────────────────────────────────────────────────────────────────
def load_url_file():
    with open(URL_FILE, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def save_url_to_file(url):
    with open(URL_FILE, "a", encoding="utf-8") as f:
        f.write(url + "\n")

def status_color(s):
    return {"OK":"#22c55e","DETECTED":"#f59e0b","NOTIFIED":"#3b82f6",
            "RETESTED":"#a855f7","ESCALATED":"#ef4444","RESOLVED":"#10b981"}.get(s,"#6b7280")

def _url_host_is_ip(url):
    """Return (True, ip_str) if the host part of *url* is a raw IP address."""
    import ipaddress
    from urllib.parse import urlparse
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True, host
    except ValueError:
        return False, ""

# ── HTML template ──────────────────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Exposure Monitor — IITM Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:#0a0f1e;--surface:#111827;--card:#1a2236;--border:#1e2d45;
    --text:#e2e8f0;--muted:#64748b;--accent:#3b82f6;--accent2:#6366f1;
    --green:#22c55e;--yellow:#f59e0b;--red:#ef4444;--purple:#a855f7;--teal:#10b981;
  }
  body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}

  /* ── NAV ── */
  nav{background:var(--surface);border-bottom:1px solid var(--border);
      padding:0 2rem;display:flex;align-items:center;justify-content:space-between;height:64px;
      position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}
  .nav-brand{display:flex;align-items:center;gap:.75rem;font-weight:700;font-size:1.1rem}
  .nav-brand .dot{width:10px;height:10px;border-radius:50%;background:var(--green);
                  box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  .nav-right{font-size:.8rem;color:var(--muted)}

  /* ── LAYOUT ── */
  .container{max-width:1400px;margin:0 auto;padding:2rem}
  .page-title{font-size:1.8rem;font-weight:800;margin-bottom:.25rem;
    background:linear-gradient(135deg,#60a5fa,#818cf8);-webkit-background-clip:text;
    -webkit-text-fill-color:transparent}
  .page-sub{color:var(--muted);font-size:.9rem;margin-bottom:2rem}

  /* ── STAT CARDS ── */
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:12px;
        padding:1.25rem;text-align:center;transition:transform .2s}
  .stat:hover{transform:translateY(-2px)}
  .stat .val{font-size:2rem;font-weight:800;line-height:1}
  .stat .lbl{font-size:.75rem;color:var(--muted);margin-top:.4rem;text-transform:uppercase;letter-spacing:.05em}

  /* ── ADD URL PANEL ── */
  .add-panel{background:var(--card);border:1px solid var(--border);border-radius:16px;
             padding:1.5rem;margin-bottom:2rem}
  .add-panel h2{font-size:1rem;font-weight:600;margin-bottom:1rem;color:#93c5fd}
  .add-form{display:flex;gap:.75rem;flex-wrap:wrap}
  .add-form input{flex:1;min-width:280px;background:#0d1626;border:1px solid var(--border);
    border-radius:8px;padding:.7rem 1rem;color:var(--text);font-size:.9rem;outline:none;
    transition:border-color .2s}
  .add-form input:focus{border-color:var(--accent)}
  .add-form input::placeholder{color:var(--muted)}
  .btn{padding:.7rem 1.4rem;border:none;border-radius:8px;font-size:.875rem;
       font-weight:600;cursor:pointer;transition:all .2s}
  .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff}
  .btn-primary:hover{opacity:.85;transform:translateY(-1px)}
  .btn-scan{background:#1e3a5f;color:#93c5fd;border:1px solid #2563eb}
  .btn-scan:hover{background:#1e40af;color:#fff}
  .btn-danger{background:#3f1010;color:#f87171;border:1px solid #dc2626}
  .btn-danger:hover{background:#7f1d1d;color:#fff}
  .btn-sm{padding:.35rem .8rem;font-size:.78rem}

  /* ── FILTER BAR ── */
  .filter-bar{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}
  .filter-btn{padding:.4rem .9rem;border-radius:20px;border:1px solid var(--border);
    background:transparent;color:var(--muted);font-size:.78rem;cursor:pointer;transition:all .2s}
  .filter-btn.active,.filter-btn:hover{background:var(--accent);border-color:var(--accent);color:#fff}

  /* ── TABLE ── */
  .table-wrap{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}
  .table-header{padding:1rem 1.5rem;border-bottom:1px solid var(--border);
    display:flex;align-items:center;justify-content:space-between}
  .table-header h2{font-size:1rem;font-weight:600}
  table{width:100%;border-collapse:collapse}
  th{padding:.75rem 1rem;text-align:left;font-size:.72rem;font-weight:600;
     color:var(--muted);text-transform:uppercase;letter-spacing:.08em;
     background:#0f1a2e;border-bottom:1px solid var(--border)}
  td{padding:.8rem 1rem;font-size:.83rem;border-bottom:1px solid #0f1a2e;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#162032}

  .badge{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .65rem;
         border-radius:20px;font-size:.72rem;font-weight:700;letter-spacing:.04em}
  .url-cell{font-family:monospace;font-size:.78rem;color:#93c5fd;max-width:360px;
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .time-cell{color:var(--muted);font-size:.76rem}
  .actions{display:flex;gap:.4rem}

  /* ── TOAST ── */
  #toast{position:fixed;bottom:2rem;right:2rem;background:#1e293b;border:1px solid #334155;
    color:#e2e8f0;padding:1rem 1.5rem;border-radius:12px;font-size:.875rem;
    display:none;z-index:999;box-shadow:0 8px 32px rgba(0,0,0,.5)}

  /* ── MODAL ── */
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;
    display:none;align-items:center;justify-content:center}
  .modal-overlay.show{display:flex}
  .modal{background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:2rem;width:90%;max-width:480px}
  .modal h3{margin-bottom:1rem;font-size:1.1rem}
  .modal p{color:var(--muted);font-size:.875rem;margin-bottom:1.5rem}
  .modal-actions{display:flex;gap:.75rem;justify-content:flex-end}

  .search-box{background:#0d1626;border:1px solid var(--border);border-radius:8px;
    padding:.5rem 1rem;color:var(--text);font-size:.85rem;outline:none;width:220px}
  .search-box:focus{border-color:var(--accent)}
  .empty{text-align:center;padding:3rem;color:var(--muted);font-size:.9rem}

  @media(max-width:768px){.add-form{flex-direction:column}.stats{grid-template-columns:repeat(3,1fr)}}
</style>
</head>
<body>

<nav>
  <div class="nav-brand">
    <span class="dot"></span>
    DNS Exposure Monitor
  </div>
  <div class="nav-right" id="last-refresh">IITM · Auto-refresh every 30s</div>
</nav>

<div class="container">
  <div class="page-title">Security Dashboard</div>
  <div class="page-sub">Monitor raw IP exposures across IITM subdomains in real-time</div>

  <!-- STATS -->
  <div class="stats" id="stats-row">
    {% for label, val, color in stats %}
    <div class="stat">
      <div class="val" style="color:{{color}}">{{val}}</div>
      <div class="lbl">{{label}}</div>
    </div>
    {% endfor %}
  </div>

  <!-- ADD URL PANEL -->
  <div class="add-panel">
    <h2>+ Add URL / IP to Monitor</h2>
    <form class="add-form" id="addForm" onsubmit="addUrl(event)">
      <input id="urlInput" type="text" placeholder="https://example.iitm.ac.in  or  http://10.24.x.x"
             autocomplete="off" spellcheck="false" required>
      <button type="submit" class="btn btn-primary">Add & Scan Now</button>
    </form>
    <div id="addMsg" style="margin-top:.75rem;font-size:.82rem;color:var(--muted)"></div>
  </div>

  <!-- FILTER + TABLE -->
  <div class="filter-bar">
    <button class="filter-btn active" onclick="setFilter('ALL',this)">All ({{total}})</button>
    {% for s,cnt,col in filters %}
    <button class="filter-btn" onclick="setFilter('{{s}}',this)"
            style="--fc:{{col}}">{{s}} ({{cnt}})</button>
    {% endfor %}
  </div>

  <div class="table-wrap">
    <div class="table-header">
      <h2>Monitored URLs</h2>
      <div style="display:flex;gap:.75rem;align-items:center">
        <input class="search-box" placeholder="Search..." oninput="filterTable(this.value)">
        <button class="btn btn-scan" onclick="triggerScan()">Run Scan Now</button>
      </div>
    </div>
    <table id="mainTable">
      <thead>
        <tr>
          <th>#</th><th>URL</th><th>Status</th><th>IP / Final Host</th>
          <th>First Detected</th><th>Last Checked</th><th>Retests</th><th>Actions</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {% for i, r in rows %}
        <tr data-status="{{r.status}}" data-url="{{r.url}}">
          <td style="color:var(--muted)">{{i}}</td>
          <td class="url-cell" title="{{r.url}}">
            <a href="{{r.url}}" target="_blank" style="color:#93c5fd;text-decoration:none">{{r.url}}</a>
          </td>
          <td>
            <span class="badge" style="background:{{r.color}}22;color:{{r.color}};border:1px solid {{r.color}}44">
              <span style="width:6px;height:6px;border-radius:50%;background:{{r.color}};display:inline-block"></span>
              {{r.status}}
            </span>
          </td>
          <td style="font-family:monospace;font-size:.78rem;color:{% if r.is_ip %}#f87171{% else %}var(--muted){% endif %}">
            {{r.host or '—'}}
          </td>
          <td class="time-cell">{{r.first_det or '—'}}</td>
          <td class="time-cell">{{r.last_chk or '—'}}</td>
          <td style="text-align:center;color:{% if r.retests > 0 %}#f59e0b{% else %}var(--muted){% endif %}">
            {{r.retests}}
          </td>
          <td class="actions">
            <button class="btn btn-scan btn-sm" onclick="scanOne('{{r.url}}')">Scan</button>
            <button class="btn btn-danger btn-sm" onclick="confirmDelete('{{r.url}}')">Remove</button>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% if not rows %}<div class="empty">No URLs being monitored yet. Add one above.</div>{% endif %}
  </div>
</div>

<!-- DELETE MODAL -->
<div class="modal-overlay" id="deleteModal">
  <div class="modal">
    <h3>Remove URL?</h3>
    <p id="deleteUrlText"></p>
    <div class="modal-actions">
      <button class="btn" style="background:#1e293b;color:var(--muted)" onclick="closeModal()">Cancel</button>
      <button class="btn btn-danger" onclick="doDelete()">Remove</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
let currentFilter = 'ALL';
let deleteTarget = '';

function toast(msg, color='#22c55e') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.borderColor = color;
  t.style.display = 'block';
  setTimeout(() => t.style.display='none', 3500);
}

function setFilter(status, btn) {
  currentFilter = status;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable(document.querySelector('.search-box').value);
}

function filterTable(search) {
  const rows = document.querySelectorAll('#tableBody tr');
  rows.forEach(r => {
    const statusMatch = currentFilter === 'ALL' || r.dataset.status === currentFilter;
    const searchMatch = !search || r.dataset.url.toLowerCase().includes(search.toLowerCase());
    r.style.display = (statusMatch && searchMatch) ? '' : 'none';
  });
}

async function addUrl(e) {
  e.preventDefault();
  const url = document.getElementById('urlInput').value.trim();
  const msg = document.getElementById('addMsg');
  msg.style.color = '#64748b';
  msg.textContent = 'Scanning & adding...';
  try {
    const res = await fetch('/api/add', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({url})});
    const data = await res.json();
    if (data.ok) {
      toast(data.message);
      msg.style.color = '#22c55e';
      msg.textContent = data.message;
      document.getElementById('urlInput').value = '';
      setTimeout(() => location.reload(), 1800);
    } else {
      msg.style.color = '#f87171';
      msg.textContent = data.message;
      toast(data.message, '#ef4444');
    }
  } catch(err) {
    msg.style.color = '#f87171';
    msg.textContent = 'Request failed: ' + err;
  }
}

async function scanOne(url) {
  toast('Scanning ' + url + '...', '#3b82f6');
  const res = await fetch('/api/scan-one', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url})});
  const data = await res.json();
  toast(data.message, data.is_ip ? '#ef4444' : '#22c55e');
  setTimeout(() => location.reload(), 2000);
}

async function triggerScan() {
  toast('Full scan started — this may take a few minutes...', '#3b82f6');
  const res = await fetch('/api/scan-all', {method:'POST'});
  const data = await res.json();
  toast(data.message);
  setTimeout(() => location.reload(), 3000);
}

function confirmDelete(url) {
  deleteTarget = url;
  document.getElementById('deleteUrlText').textContent = url;
  document.getElementById('deleteModal').classList.add('show');
}
function closeModal() {
  document.getElementById('deleteModal').classList.remove('show');
}
async function doDelete() {
  closeModal();
  const res = await fetch('/api/remove', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url: deleteTarget})});
  const data = await res.json();
  toast(data.message, '#f59e0b');
  setTimeout(() => location.reload(), 1500);
}

// Auto-refresh every 30s
setInterval(() => location.reload(), 30000);
document.getElementById('last-refresh').textContent =
  'IITM · Last refreshed: ' + new Date().toLocaleTimeString();
</script>
</body>
</html>
"""

# ── route helpers ──────────────────────────────────────────────────────────
def get_dashboard_data():
    with db.get_connection() as conn:
        rows_raw = db.get_all_records(conn)

    STATUSES = ["OK","DETECTED","NOTIFIED","RETESTED","ESCALATED","RESOLVED"]
    counts = {s:0 for s in STATUSES}
    rows = []

    for i, r in enumerate(rows_raw, 1):
        st = r["current_status"]
        counts[st] = counts.get(st, 0) + 1
        host = ""
        final = r["last_final_url_seen"] or ""
        if final:
            from urllib.parse import urlparse
            host = urlparse(final).hostname or ""

        import re
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host))

        def fmt(t):
            if not t: return ""
            try:
                dt = datetime.fromisoformat(t)
                return dt.strftime("%d %b %H:%M")
            except: return t

        rows.append((i, type('R', (), {
            "url": r["url"],
            "status": st,
            "color": status_color(st),
            "host": host,
            "is_ip": is_ip,
            "first_det": fmt(r["first_detected_time"]),
            "last_chk": fmt(r["last_checked_time"]),
            "retests": r["retest_count"] or 0,
        })()))

    colors = {"OK":"#22c55e","DETECTED":"#f59e0b","NOTIFIED":"#3b82f6",
              "RETESTED":"#a855f7","ESCALATED":"#ef4444","RESOLVED":"#10b981"}
    total = len(rows_raw)
    stats = [(s, counts[s], colors[s]) for s in STATUSES]
    stats.append(("TOTAL", total, "#60a5fa"))
    filters = [(s, counts[s], colors[s]) for s in STATUSES if counts[s] > 0]
    return rows, stats, filters, total


@app.route("/")
def index():
    # Sync any URLs added directly to the file into the DB, and remove URLs no longer in the file
    with db.get_connection() as conn:
        file_urls = load_url_file()
        # Add/update all URLs from the file
        for url in file_urls:
            db.upsert_url(conn, url)
        # Delete all URLs from DB that are NOT in the file
        # First get all URLs in DB
        all_db_urls = [row["url"] for row in db.get_all_records(conn)]
        # Delete URLs not in file_urls
        for url in all_db_urls:
            if url not in file_urls:
                conn.execute("DELETE FROM url_status WHERE url = ?", (url,))
        conn.commit()
    rows, stats, filters, total = get_dashboard_data()
    return render_template_string(HTML, rows=rows, stats=stats, filters=filters, total=total)


@app.route("/api/add", methods=["POST"])
def api_add():
    url = (request.json or {}).get("url", "").strip()
    if not url:
        return jsonify(ok=False, message="URL cannot be empty")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    with db.get_connection() as conn:
        db.upsert_url(conn, url)

        # ── Fast-path: URL host IS already a raw IP — no connection needed ──
        host_is_ip, ip_str = _url_host_is_ip(url)
        if host_is_ip:
            existing = load_url_file()
            if url not in existing:
                save_url_to_file(url)
            record = db.get_url_record(conn, url)
            if record["current_status"] == "OK":
                db.mark_detected(conn, url, url)  # final_url = url itself
                record = db.get_url_record(conn, url)
                sent = notifier.send_detection_alert(url, ip_str, record["first_detected_time"])
                if sent:
                    db.mark_notified(conn, url)
                return jsonify(ok=True, message=f"RAW IP exposure flagged: {url} — WhatsApp alert sent!", is_ip=True)
            else:
                return jsonify(ok=True, message=f"{url} already tracked (status: {record['current_status']})", is_ip=True)

        # ── Normal path: scan to check if redirect leads to a raw IP ──
        result = scanner.check_url(url)

        # Auto-fallback: if https fails, try http (and vice versa)
        if not result.success:
            alt = url.replace("https://", "http://") if url.startswith("https://") else url.replace("http://", "https://")
            if alt != url:
                alt_result = scanner.check_url(alt)
                if alt_result.success:
                    url = alt
                    result = alt_result
                    db.upsert_url(conn, url)

        # Save the (possibly corrected) URL to file
        existing = load_url_file()
        if url not in existing:
            save_url_to_file(url)

        if result.success and result.is_raw_ip:
            record = db.get_url_record(conn, url)
            if record["current_status"] == "OK":
                db.mark_detected(conn, url, result.final_url)
                record = db.get_url_record(conn, url)
                sent = notifier.send_detection_alert(url, result.ip_detected, record["first_detected_time"])
                if sent:
                    db.mark_notified(conn, url)
            return jsonify(ok=True, message=f"RAW IP detected at {url} — WhatsApp alert sent!", is_ip=True)
        elif result.success:
            db.mark_ok(conn, url, result.final_url)
            return jsonify(ok=True, message=f"Added {url} — resolves to a proper hostname (OK)", is_ip=False)
        else:
            return jsonify(ok=True, message=f"Added {url} — unreachable right now, but added to watchlist.", is_ip=False)


@app.route("/api/scan-one", methods=["POST"])
def api_scan_one():
    url = (request.json or {}).get("url", "").strip()
    with db.get_connection() as conn:
        db.upsert_url(conn, url)
        record = db.get_url_record(conn, url)
        current = record["current_status"] if record else "OK"

        # ── Fast-path FIRST: if URL host is a raw IP, no connection needed ──
        host_is_ip, ip_str = _url_host_is_ip(url)
        if host_is_ip:
            if current == "OK":
                db.mark_detected(conn, url, url)
                rec = db.get_url_record(conn, url)
                notifier.send_detection_alert(url, ip_str, rec["first_detected_time"])
                db.mark_notified(conn, url)
                return jsonify(message=f"RAW IP flagged: {url} — WhatsApp alert sent!", is_ip=True)
            elif current in ("NOTIFIED", "RETESTED", "ESCALATED"):
                db.mark_retested(conn, url, url)
                return jsonify(message=f"{url} still a raw IP (status: {current} → RETESTED).", is_ip=True)
            else:
                return jsonify(message=f"{url} is a raw IP (status: {current}).", is_ip=True)

        # ── Normal path: run network scan only for domain-based URLs ──
        result = scanner.check_url(url)
        if result.success and result.is_raw_ip:
            if current == "OK":
                db.mark_detected(conn, url, result.final_url)
                rec = db.get_url_record(conn, url)
                notifier.send_detection_alert(url, result.ip_detected, rec["first_detected_time"])
                db.mark_notified(conn, url)
            else:
                db.mark_retested(conn, url, result.final_url)
            return jsonify(message=f"RAW IP confirmed at {url}! Alert sent.", is_ip=True)
        elif result.success:
            if current not in ("OK",):
                db.mark_resolved(conn, url, result.final_url)
                notifier.send_resolution_alert(url)
            else:
                db.mark_ok(conn, url, result.final_url)
            return jsonify(message=f"{url} is OK — resolves to a proper hostname.", is_ip=False)
        else:
            return jsonify(message=f"Could not reach {url}: {(result.error or '')[:60]}", is_ip=False)


@app.route("/api/scan-all", methods=["POST"])
def api_scan_all():
    import threading
    from scheduler import scan_all_urls
    # First sync file → DB so manually-added URLs are included
    with db.get_connection() as conn:
        for url in load_url_file():
            db.upsert_url(conn, url)
    threading.Thread(target=scan_all_urls, daemon=True).start()
    return jsonify(message="Full scan started in background. Refresh in ~2 minutes.")


@app.route("/api/remove", methods=["POST"])
def api_remove():
    url = (request.json or {}).get("url", "").strip()
    # Remove from file
    lines = load_url_file()
    lines = [l for l in lines if l != url]
    with open(URL_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    # Remove from DB
    with db.get_connection() as conn:
        conn.execute("DELETE FROM url_status WHERE url = ?", (url,))
        conn.commit()
    return jsonify(message=f"Removed {url} from monitoring.")


if __name__ == "__main__":
    print("Dashboard running at http://127.0.0.1:5000")
    app.run(debug=False, port=5000)

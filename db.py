"""
db.py
=====
SQLite schema creation and all state-machine transition helpers.

States
------
OK        – resolves to a hostname, no issue
DETECTED  – raw IP found for the first time
NOTIFIED  – admin has been WhatsApp-alerted
RETESTED  – rechecked while issue persists (retest_count incremented)
ESCALATED – unresolved past threshold (retest_count >= limit OR 48 h elapsed)
RESOLVED  – issue fixed, now resolves to a hostname again
"""

import sqlite3
import logging
from datetime import datetime, timezone
from typing import Optional

from config import DB_PATH

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column names kept as constants to avoid typos
# ---------------------------------------------------------------------------
STATES = ("OK", "DETECTED", "NOTIFIED", "RETESTED", "ESCALATED", "RESOLVED")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS url_status (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    url                 TEXT    NOT NULL UNIQUE,
    current_status      TEXT    NOT NULL DEFAULT 'OK',
    first_detected_time TEXT,           -- ISO-8601 UTC, set when issue first found
    last_checked_time   TEXT    NOT NULL,
    retest_count        INTEGER NOT NULL DEFAULT 0,
    last_final_url_seen TEXT
);
"""


def get_connection() -> sqlite3.Connection:
    """Return a thread-safe SQLite connection with row_factory set and timeout for concurrency."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    with get_connection() as conn:
        conn.executescript(_SCHEMA)
    logger.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_url(conn: sqlite3.Connection, url: str) -> None:
    """Insert a URL with status OK if it doesn't already exist."""
    conn.execute(
        """
        INSERT OR IGNORE INTO url_status (url, current_status, last_checked_time)
        VALUES (?, 'OK', ?)
        """,
        (url, _now_utc()),
    )
    conn.commit()


def get_url_record(conn: sqlite3.Connection, url: str) -> Optional[sqlite3.Row]:
    """Fetch the full record for a URL, or None if not found."""
    cur = conn.execute("SELECT * FROM url_status WHERE url = ?", (url,))
    return cur.fetchone()


def get_all_records(conn: sqlite3.Connection) -> list:
    """Return all rows."""
    cur = conn.execute("SELECT * FROM url_status ORDER BY url")
    return cur.fetchall()


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------
def mark_ok(conn: sqlite3.Connection, url: str, final_url: str) -> None:
    """URL resolves fine — ensure status is OK, reset counters."""
    record = get_url_record(conn, url)
    old_status = record["current_status"] if record else "OK"
    conn.execute(
        """
        UPDATE url_status
        SET current_status      = 'OK',
            first_detected_time = NULL,
            last_checked_time   = ?,
            retest_count        = 0,
            last_final_url_seen = ?
        WHERE url = ?
        """,
        (_now_utc(), final_url, url),
    )
    conn.commit()
    if old_status not in ("OK", None):
        logger.info("STATE TRANSITION  %s  %s → OK", url, old_status)


def mark_detected(conn: sqlite3.Connection, url: str, final_url: str) -> None:
    """Raw IP found for the first time — set DETECTED + first_detected_time."""
    now = _now_utc()
    conn.execute(
        """
        UPDATE url_status
        SET current_status      = 'DETECTED',
            first_detected_time = ?,
            last_checked_time   = ?,
            retest_count        = 0,
            last_final_url_seen = ?
        WHERE url = ?
        """,
        (now, now, final_url, url),
    )
    conn.commit()
    logger.warning("STATE TRANSITION  %s  OK → DETECTED  (final=%s)", url, final_url)


def mark_notified(conn: sqlite3.Connection, url: str) -> None:
    """Admin has been alerted — advance DETECTED → NOTIFIED."""
    conn.execute(
        """
        UPDATE url_status
        SET current_status    = 'NOTIFIED',
            last_checked_time = ?
        WHERE url = ?
        """,
        (_now_utc(), url),
    )
    conn.commit()
    logger.info("STATE TRANSITION  %s  DETECTED → NOTIFIED", url)


def mark_retested(conn: sqlite3.Connection, url: str, final_url: str) -> None:
    """Issue still present — increment retest_count, set RETESTED."""
    conn.execute(
        """
        UPDATE url_status
        SET current_status      = 'RETESTED',
            last_checked_time   = ?,
            retest_count        = retest_count + 1,
            last_final_url_seen = ?
        WHERE url = ?
        """,
        (_now_utc(), final_url, url),
    )
    conn.commit()
    record = get_url_record(conn, url)
    logger.warning(
        "STATE TRANSITION  %s  → RETESTED  (retest_count=%s)",
        url,
        record["retest_count"] if record else "?",
    )


def mark_escalated(conn: sqlite3.Connection, url: str, final_url: str) -> None:
    """Threshold crossed — mark ESCALATED."""
    conn.execute(
        """
        UPDATE url_status
        SET current_status      = 'ESCALATED',
            last_checked_time   = ?,
            last_final_url_seen = ?
        WHERE url = ?
        """,
        (_now_utc(), final_url, url),
    )
    conn.commit()
    logger.critical("STATE TRANSITION  %s  → ESCALATED", url)


def mark_resolved(conn: sqlite3.Connection, url: str, final_url: str) -> None:
    """Issue fixed — mark RESOLVED, reset counters."""
    record = get_url_record(conn, url)
    old_status = record["current_status"] if record else "?"
    conn.execute(
        """
        UPDATE url_status
        SET current_status      = 'RESOLVED',
            last_checked_time   = ?,
            retest_count        = 0,
            last_final_url_seen = ?
        WHERE url = ?
        """,
        (_now_utc(), final_url, url),
    )
    conn.commit()
    logger.info("STATE TRANSITION  %s  %s → RESOLVED", url, old_status)

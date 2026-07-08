"""
scanner.py
==========
Core URL-checking logic.

For each URL:
1. Follow all HTTP redirects (explicitly using allow_redirects=True)
2. Capture the FINAL URL after all redirects (response.url)
3. Extract the hostname from the final URL
4. Determine whether the hostname is a valid IPv4/IPv6 address
5. Log the full redirect chain (response.history) for debugging
"""

import ipaddress
import logging
import time
import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import REQUEST_TIMEOUT, REQUEST_RETRIES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    original_url: str
    final_url: str = ""
    host: str = ""
    is_raw_ip: bool = False
    ip_detected: str = ""       # set only when is_raw_ip is True
    error: Optional[str] = None
    success: bool = False       # True even when is_raw_ip; False only on network error
    redirect_chain: list[str] = field(default_factory=list)  # list of intermediate URLs


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------
def _build_session() -> requests.Session:
    """Build a requests.Session with automatic retries on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=REQUEST_RETRIES,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    # Impersonate a normal browser to avoid 403s from WAFs
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
    )
    return session


# ---------------------------------------------------------------------------
# IP detection helper
# ---------------------------------------------------------------------------
def _is_ip_address(host: str) -> bool:
    """Return True if *host* is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    host_clean = host
    # Strip port if present (e.g. "192.168.1.1:8080" → "192.168.1.1")
    if ":" in host:
        # Check if it's an IPv6 address first (has [])
        if "[" in host and "]" in host:
            host_clean = host.strip("[]")
        else:
            host_clean = host.split(":")[0]
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Single URL check
# ---------------------------------------------------------------------------
def check_url(url: str) -> ScanResult:
    """
    Check *url* and return a ScanResult.

    Network failures produce a ScanResult with success=False and error set.
    """
    result = ScanResult(original_url=url)
    session = _build_session()
    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,  # Explicitly set as per requirements
            verify=False,          # IITM has valid certs but some subdomains may not
        )
        # Log full redirect chain
        result.redirect_chain = [r.url for r in response.history]
        if result.redirect_chain:
            logger.info("Redirect chain for %s: %s", url, " -> ".join(result.redirect_chain))
        
        result.final_url = response.url
        parsed = urlparse(result.final_url)
        result.host = parsed.hostname or ""

        if _is_ip_address(result.host):
            result.is_raw_ip = True
            result.ip_detected = result.host
            logger.warning("RAW IP DETECTED  %s  ->  %s  (host=%s)", url, result.final_url, result.host)
        else:
            logger.info("OK  %s  ->  %s  (host=%s)", url, result.final_url, result.host)

        result.success = True

    except requests.exceptions.RequestException as exc:  # Catch all request-related exceptions
        result.error = f"RequestException: {exc}"
        result.success = False
        logger.warning("Request error for %s: %s", url, exc)

    except Exception as exc:  # pylint: disable=broad-except
        result.error = f"Unexpected: {exc}"
        result.success = False
        logger.error("Unexpected error for %s: %s", url, exc, exc_info=True)

    finally:
        session.close()

    return result


# ---------------------------------------------------------------------------
# URL file reader
# ---------------------------------------------------------------------------
def load_urls(filepath: str) -> list[str]:
    """
    Read URLs from *filepath*.

    Supports:
    - Plain text (.txt)  — one URL per line
    - CSV (.csv)         — first column treated as URL
    Blank lines and lines starting with '#' are skipped.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"URL file not found: {filepath}")

    urls: list[str] = []

    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if row:
                    candidate = row[0].strip()
                    if candidate and not candidate.startswith("#"):
                        urls.append(candidate)
    else:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                candidate = line.strip()
                if candidate and not candidate.startswith("#"):
                    urls.append(candidate)

    logger.info("Loaded %d URLs from %s", len(urls), filepath)
    return urls

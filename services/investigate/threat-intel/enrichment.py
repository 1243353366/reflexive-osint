"""Threat intel enrichment — public APIs, documented free tiers only.

CONSTRAINT: stay within documented free-tier rate limits. No key rotation,
no proxying, no circumvention of limits. Existing enrichment sources (OTX,
AbuseIPDB, Pulsedive, GDELT DOC API) live in the existing threat-intel base;
this module adds Shodan InternetDB, VirusTotal public API, and NVD/CVE.
Stdlib-only.
"""

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

# Documented free-tier floors. Conservative by design.
_MIN_INTERVALS = {
    "internetdb": 0.0,        # free, no key, no documented per-IP quota issue at our volume
    "virustotal": 60 / 4,      # public API: 4 requests/minute
    "nvd": 6.0,                # public NVD guidance: ~10 requests/minute without key; we use 6s
}
_last_call: Dict[str, float] = {}


def _throttle(name: str) -> None:
    """Enforce minimum spacing per source — the only rate strategy allowed."""
    now = time.monotonic()
    wait = _MIN_INTERVALS[name] - (now - _last_call.get(name, 0.0))
    if wait > 0:
        time.sleep(wait)
    _last_call[name] = time.monotonic()


def _fetch_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Any:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "reflexive-osint-investigate/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def shodan_internetdb(ip: str) -> Dict[str, Any]:
    """Shodan InternetDB — free, no key required. https://internetdb.shodan.io/{ip}"""
    _throttle("internetdb")
    try:
        return _fetch_json(f"https://internetdb.shodan.io/{ip}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ip": ip, "found": False}
        raise


def virustotal_ip_report(ip: str) -> Dict[str, Any]:
    """VirusTotal public API (v3) — requires VT_API_KEY, 4 req/min quota."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"error": "VT_API_KEY not set; skipping VirusTotal enrichment"}
    _throttle("virustotal")
    return _fetch_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key, "User-Agent": "reflexive-osint-investigate/0.1"},
    )


def nvd_cve_search(keyword: str, max_results: int = 10, pub_start: Optional[str] = None) -> Dict[str, Any]:
    """NVD CVE feed (2.0 API), no key needed for public use; 6s spacing enforced."""
    _throttle("nvd")
    q = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={max_results}"
    if pub_start:
        q += f"&pubStartDate={pub_start}0000"
    return _fetch_json(q, timeout=60)


def enrich(ip: str) -> Dict[str, Any]:
    """Combine free-tier enrichments for one IP. Rate-limited per source."""
    return {
        "ip": ip,
        "shodan": shodan_internetdb(ip),
        "virustotal": virustotal_ip_report(ip),
    }

"""Corporate filings client — calls the isolated openEDGAR service.

The openEDGAR fork (1243353366/openedgar, MIT, NOTICE at its root) runs as an
external service. This client speaks HTTP to it and maps responses into
Company / Filing / Person records for the aggregator. Stdlib-only.
"""

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

OPENEDGAR_URL = os.environ.get("OPENEDGAR_URL", "http://localhost:8000")


def _get(path: str, timeout: int = 30) -> Any:
    url = f"{OPENEDGAR_URL.rstrip('/')}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_company(cik: str) -> Dict[str, Any]:
    """Fetch a company by CIK and normalize for ingest_companies()."""
    raw = _get(f"/api/company/{cik}")
    return {
        "name": raw.get("name"),
        "aliases": raw.get("former_names", []),
        "cik": raw.get("cik", cik),
        "jurisdiction": raw.get("state_of_incorporation"),
    }


def get_filings(cik: str, forms: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Fetch recent filings for a CIK and normalize for ingest_filings()."""
    q = ""
    if forms:
        q = "?forms=" + ",".join(forms)
    raw = _get(f"/api/filings/{cik}{q}")
    return [
        {
            "accession_no": f.get("accession_no"),
            "form_type": f.get("form_type"),
            "filed_at": f.get("filing_date"),
            "company_name": f.get("company_name"),
            "company_cik": cik,
            "url": f.get("url"),
        }
        for f in raw.get("filings", [])
    ]


def get_persons_for_filing(accession_no: str) -> List[Dict[str, Any]]:
    """Fetch signing officers/directors for a filing → ingest_persons()."""
    raw = _get(f"/api/filing/{accession_no}/persons")
    return [
        {
            "name": p.get("name"),
            "aliases": [],
            "roles": [
                {
                    "title": p.get("title"),
                    "organization": p.get("company_name"),
                    "start": p.get("period_start"),
                    "end": p.get("period_end"),
                }
            ],
        }
        for p in raw.get("persons", [])
    ]


def collect_company_graph(cik: str, forms: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Pull one company's records in aggregator-ready form."""
    company = get_company(cik)
    filings = get_filings(cik, forms)
    persons: List[Dict[str, Any]] = []
    for f in filings[:20]:  # cap: stay conservative with the upstream service
        persons.extend(get_persons_for_filing(f["accession_no"]))
    return {"companies": [company], "filings": filings, "persons": persons}

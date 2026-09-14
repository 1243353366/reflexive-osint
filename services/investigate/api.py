"""API boundary for Investigate Mode v2.

Every module is reached through this surface; nothing imports fork code
directly. The gitleaks/openEDGAR/sugartrail services run externally and are
called over HTTP or subprocess by their adapters.

Requires: fastapi, uvicorn (pip install fastapi uvicorn).
Run:  uvicorn api:app --port 8010  (from services/investigate/)
"""

import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "osint-aggregation"))
sys.path.insert(0, str(Path(__file__).parent / "exposure-scanner"))
sys.path.insert(0, str(Path(__file__).parent / "corporate-filings"))
sys.path.insert(0, str(Path(__file__).parent / "threat-intel"))

from aggregator import Aggregator  # noqa: E402
from corporate_filings_client import collect_company_graph as edgar_collect  # noqa: E402
from scan import scan_target  # noqa: E402

app = FastAPI(title="Investigate Mode v2 — OSINT Aggregation", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for the real Brighthatch origin
    allow_methods=["GET", "POST"],
)


class ScanRequest(BaseModel):
    target: str
    organization: Optional[str] = None


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "mode": "investigate-v2"}


@app.post("/api/v1/scan")
def scan(req: ScanRequest) -> dict:
    """DETECT-ONLY exposure scan of a local target via the gitleaks service.

    Returns flagged ExposedSecret records. No verification of found
    credentials exists on any path behind this API.
    """
    if not Path(req.target).exists():
        raise HTTPException(status_code=400, detail="target path does not exist")
    findings = scan_target(req.target, req.organization)
    agg = Aggregator()
    agg.ingest_exposed_secrets(findings, source="gitleaks")
    return {"findings": findings, "graph": agg.graph.to_dict()}


@app.get("/api/v1/company/{cik}")
def company_graph(cik: str, forms: Optional[str] = None) -> dict:
    """Corporate relationship subgraph for one CIK via the openEDGAR service."""
    form_list = forms.split(",") if forms else None
    data = edgar_collect(cik, form_list)
    agg = Aggregator()
    agg.ingest_companies(data["companies"], source="openedgar")
    agg.ingest_filings(data["filings"], source="openedgar")
    agg.ingest_persons(data["persons"], source="openedgar")
    return {"graph": agg.graph.to_dict(), "cytoscape": agg.export_cytoscape()}


@app.get("/api/v1/graph")
def empty_graph() -> dict:
    """Empty graph skeleton — used by viz/cytoscape.html to verify wiring."""
    agg = Aggregator()
    return {"graph": agg.graph.to_dict(), "cytoscape": agg.export_cytoscape()}

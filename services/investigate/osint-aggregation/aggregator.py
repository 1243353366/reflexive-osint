"""Multi-source OSINT aggregator for Investigate Mode v2.

Clean-room reimplementation: the aggregation → entity-relationship graph
pattern is architecture inspired by Palantir-OSINT (JehanPatel); no code from
that repository is incorporated. Stdlib-only.
"""

import hashlib
import re
from typing import Any, Dict, List

from graph import Graph

# Legal-suffix tokens dropped when canonicalizing organization names.
# Token-based, so "MegaCorp" is never mangled (only standalone suffix words drop).
_ORG_SUFFIX_TOKENS = frozenset(
    {
        "inc", "incorporated", "llc", "ltd", "limited",
        "corp", "corporation", "co", "company", "plc",
        "gmbh", "ag", "sa", "nv", "bv",
    }
)


def canonical_org_key(name: str) -> str:
    """Canonical dedup key for organizations (suffix tokens dropped)."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]
    return " ".join(t for t in tokens if t not in _ORG_SUFFIX_TOKENS)


def canonical_person_key(name: str) -> str:
    """Canonical dedup key for people (full-name, normalized)."""
    n = re.sub(r"[^a-z0-9 ]+", " ", name.lower())
    return re.sub(r"\s+", " ", n).strip()


def fingerprint_secret(secret_value: str) -> str:
    """Truncated SHA-256 of a discovered secret — the ONLY thing ever stored.

    HARD CONSTRAINT (see schema/entities.json): ExposedSecret nodes hold this
    fingerprint, never the secret material.
    """
    return hashlib.sha256(secret_value.encode("utf-8", errors="replace")).hexdigest()[:12]


class Aggregator:
    """Merges normalized records from multiple sources into one Graph."""

    def __init__(self) -> None:
        self.graph = Graph()

    # -- ingestion -------------------------------------------------------

    def ingest_companies(self, records: List[Dict[str, Any]], source: str) -> None:
        """records: [{name, aliases?, cik?, jurisdiction?, parent_cik?}]"""
        for r in records:
            key = f"company:{canonical_org_key(r['name'])}"
            self.graph.add_node(
                "Company",
                key,
                name=r["name"],
                aliases=r.get("aliases", []),
                cik=r.get("cik"),
                jurisdiction=r.get("jurisdiction"),
                canonical_key=key,
                sources=[source],
            )
            if r.get("parent_cik"):
                parent_name = r.get("parent_name")
                if parent_name:
                    pkey = f"company:{canonical_org_key(parent_name)}"
                    self.graph.add_node(
                        "Company",
                        pkey,
                        name=parent_name,
                        cik=r["parent_cik"],
                        sources=[source],
                    )
                    self.graph.add_edge("subsidiary_of", key, pkey, via=source)

    def ingest_filings(self, records: List[Dict[str, Any]], source: str) -> None:
        """records: [{accession_no, form_type, filed_at, company_name, company_cik?, url?}]"""
        for r in records:
            ckey = f"company:{canonical_org_key(r['company_name'])}"
            self.graph.add_node(
                "Company",
                ckey,
                name=r["company_name"],
                cik=r.get("company_cik"),
                sources=[source],
            )
            fkey = f"filing:{r['accession_no']}"
            self.graph.add_node(
                "Filing",
                fkey,
                accession_no=r["accession_no"],
                form_type=r.get("form_type"),
                filed_at=r.get("filed_at"),
                company_cik=r.get("company_cik"),
                url=r.get("url"),
                sources=[source],
            )
            self.graph.add_edge("filed_by", fkey, ckey, via=source)

    def ingest_persons(self, records: List[Dict[str, Any]], source: str) -> None:
        """records: [{name, aliases?, roles?: [{title, organization, start?, end?}] , company_ciks?}]"""
        for r in records:
            key = f"person:{canonical_person_key(r['name'])}"
            self.graph.add_node(
                "Person",
                key,
                name=r["name"],
                aliases=r.get("aliases", []),
                roles=r.get("roles", []),
                canonical_key=key,
                sources=[source],
            )
            for role in r.get("roles", []):
                org = role.get("organization")
                if org:
                    okey = f"company:{canonical_org_key(org)}"
                    self.graph.add_node("Company", okey, name=org, sources=[source])
                    self.graph.add_edge("exec_overlap", key, okey, via=source)

    def ingest_exposed_secrets(self, records: List[Dict[str, Any]], source: str) -> None:
        """records: [{finding_id, rule_id, kind, entropy, fingerprint, commit_ref?,
                      repository_url?, bucket_arn?, organization?, detected_at?}]

        HARD CONSTRAINT: records must already be fingerprinted upstream
        (exposure-scanner/scan.py). This module stores and forwards only.
        """
        for r in records:
            key = f"secret:{r['finding_id']}"
            self.graph.add_node(
                "ExposedSecret",
                key,
                finding_id=r["finding_id"],
                rule_id=r.get("rule_id"),
                kind=r.get("kind"),
                entropy=r.get("entropy"),
                fingerprint=r.get("fingerprint"),
                commit_ref=r.get("commit_ref"),
                detected_at=r.get("detected_at"),
                status="flagged",  # always; no verification step exists
                sources=[source],
            )
            if r.get("repository_url"):
                rkey = f"repo:{r['repository_url']}"
                self.graph.add_node(
                    "Repository", rkey, url=r["repository_url"], sources=[source]
                )
                self.graph.add_edge("exposed_in", key, rkey, via=source)
                if r.get("organization"):
                    okey = f"company:{canonical_org_key(r['organization'])}"
                    self.graph.add_node("Company", okey, name=r["organization"], sources=[source])
                    self.graph.add_edge("owns_repository", okey, rkey, via=source)
            if r.get("bucket_arn"):
                bkey = f"bucket:{r['bucket_arn']}"
                self.graph.add_node(
                    "Bucket",
                    bkey,
                    provider=r.get("provider", "unknown"),
                    name_or_arn=r["bucket_arn"],
                    region=r.get("region"),
                    sources=[source],
                )
                self.graph.add_edge("bucket_of", key, bkey, via=source)

    # -- output ----------------------------------------------------------

    def export_cytoscape(self) -> List[Dict[str, Any]]:
        return self.graph.to_cytoscape()

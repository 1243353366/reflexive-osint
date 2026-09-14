"""Exposure scanner adapter — DETECTION ONLY.

Calls the isolated gitleaks service (fork: 1243353366/gitleaks, MIT, NOTICE at
its root) over the API boundary and converts findings into ExposedSecret
entities.

HARD CONSTRAINT — ENFORCED BY DESIGN:
    No authentication, credential injection, verification, or live calls
    using any discovered secret. There is no code path in this module that
    uses a found credential. Findings are fingerprinted and flagged. Full
    stop. Any PR adding a "verify this key works" flow must be rejected
    (see services/investigate/README.md).
"""

import hashlib
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional


def run_gitleaks(target: str, timeout: int = 600) -> List[Dict[str, Any]]:
    """Run the external gitleaks service against a local target path.

    Uses `gitleaks detect --report-format json` — detect/flag only.
    The secret material is used for fingerprinting and immediately dropped.
    """
    cmd = [
        "gitleaks",
        "detect",
        "--source", target,
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--no-banner",
        "--redact",  # upstream redaction as first line of defense
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    # gitleaks exits 1 when findings exist — that is success for detection.
    if proc.returncode not in (0, 1):
        print(f"gitleaks error: {proc.stderr}", file=sys.stderr)
        return []
    try:
        return json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []


def parse_gitleaks_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one gitleaks finding into an ExposedSecret record.

    The `Secret` field (when present, despite --redact) is reduced to a
    truncated SHA-256 fingerprint and never propagated further.
    """
    secret_value = finding.get("Secret") or finding.get("match") or ""
    fingerprint = hashlib.sha256(
        secret_value.encode("utf-8", errors="replace")
    ).hexdigest()[:12] if secret_value else None

    return {
        "finding_id": finding.get("Fingerprint")
        or f"{finding.get('RuleID', 'unknown')}:{fingerprint or 'nofp'}",
        "rule_id": finding.get("RuleID"),
        "kind": finding.get("Description") or finding.get("RuleID"),
        "entropy": finding.get("Entropy"),
        "fingerprint": fingerprint,
        "commit_ref": finding.get("Commit") or finding.get("CommitSHA"),
        "repository_url": finding.get("File"),  # repo-relative path from gitleaks
        "detected_at": finding.get("AuthorDate") or finding.get("Date"),
        "status": "flagged",
    }


def scan_target(target: str, organization: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan a target and return ExposedSecret records for the aggregator.

    NOTE: detection and flagging only. Nothing here (or downstream) attempts
    to authenticate with a discovered credential.
    """
    records: List[Dict[str, Any]] = []
    for finding in run_gitleaks(target):
        record = parse_gitleaks_finding(finding)
        if organization:
            record["organization"] = organization
        records.append(record)
    return records


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Detect-only exposure scan (gitleaks service)")
    ap.add_argument("target", help="Path to scan (repo, dir, or file)")
    ap.add_argument("--org", default=None, help="Organization to attribute findings to")
    args = ap.parse_args()
    out = scan_target(args.target, args.org)
    print(json.dumps(out, indent=2))

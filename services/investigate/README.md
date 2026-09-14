# Investigate Mode v2 — OSINT Aggregation & Relationship Graph

> **Status — early scaffolding.** Functional service shells wired to the
> isolated forks. Not production-hardened; the repository's self-skepticism
> applies. No third-party code is merged here — forked projects
> ([gitleaks](https://github.com/1243353366/gitleaks),
> [openEDGAR](https://github.com/1243353366/openedgar),
> [sugartrail](https://github.com/1243353366/sugartrail)) run as external
> services and are called over the API boundary.

## Layout

| Module | Purpose | Backing service |
|---|---|---|
| `schema/entities.json` | Entity + edge type definitions for the relationship graph | — |
| `osint-aggregation/` | Multi-source aggregation → entity-relationship graph (clean-room reimplementation, architecture inspired by [Palantir-OSINT](https://github.com/JehanPatel/Palantir-OSINT) — no code incorporated) | internal |
| `exposure-scanner/` | Secret/credential exposure detection for Defend + Investigate modes | gitleaks fork (MIT) |
| `corporate-filings/` | Company / Filing / Person / Subsidiary model from SEC EDGAR | openEDGAR fork (MIT) |
| `threat-intel/` | Enrichment: Shodan InternetDB, VirusTotal public, NVD/CVE | public APIs, free-tier |
| `api.py` | The API boundary — all modules are reached through this | — |
| `viz/cytoscape.html` | Cytoscape.js graph viewer | — |

## HARD CONSTRAINTS (enforced in review; violating PRs are rejected)

1. **Detection-only exposure scanning.** Never authenticate, verify, or make
   live calls using any discovered credential. No "verify this key works"
   step, ever, under any framing.
2. **No secret retention.** `ExposedSecret` entities store a fingerprint
   (truncated SHA-256) — never the secret material.
3. **Free-tier rate limits only.** No key rotation or proxying to circumvent
   documented limits.
4. **No third-party code merged into this repo.** Forks stay behind the API
   boundary until human license-compatibility sign-off (pending, tracked in
   [docs/08](../../docs/08-investigate-mode-v2.md)).

## Attribution

Upstream authors are credited in each fork's NOTICE file, in the root
[README](../../README.md), and in [CREDITS.md](../../CREDITS.md).

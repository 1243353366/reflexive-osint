# Part 08 — Investigate Mode v2: OSINT Aggregation & Relationship Graph

> **Status — Conceptual.** This part specifies the v2 extension of Brighthatch's
> Investigate mode: a multi-source OSINT aggregation layer feeding an
> entity-relationship graph. Forked external code lives in isolated services
> behind the API boundary; nothing below merges third-party code into this
> repository's core. License gate results and fork records are included so the
> provenance chain is auditable.

## Design provenance

The multi-source aggregation → entity-relationship graph → Cytoscape.js
visualization pattern was **inspired by** [Palantir-OSINT by
@JehanPatel](https://github.com/JehanPatel/Palantir-OSINT). That repository
carries **no license file** (verified 2026-09-14: no LICENSE on any branch).
Its code has **not** been forked, vendored, or copied. The architecture was
reimplemented independently, clean-room, from the public README's description
of the design. If the author later grants a license, re-run the license gate
before any actual code is merged.

## License gate record (run 2026-09-14, before any fork)

| Source | License | Verdict |
|---|---|---|
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT (Zachary Rice, 2019) | ✅ Cleared — forked |
| [LexPredict/openedgar](https://github.com/LexPredict/openedgar) | MIT (LexPredict, 2018) | ✅ Cleared — forked |
| [JehanPatel/Palantir-OSINT](https://github.com/JehanPatel/Palantir-OSINT) | **None** | 🛑 Architecture reference only — no fork, no vendoring |
| [bellingcat/sugartrail](https://github.com/bellingcat/sugartrail) | MIT (Sean Greaves, 2022) | ✅ Cleared — forked |
| [bellingcat/EDGAR](https://github.com/bellingcat/EDGAR) | GPL-3.0 | 🛑 **EXCLUDED** — copyleft; also redundant with openEDGAR |

Policy: MIT / BSD / Apache-2.0 → proceed. GPL / AGPL / any copyleft → stop,
API-boundary integration only, no code merge. No LICENSE file → stop, treat as
architecture reference only. Bellingcat's org is a **mixed-license org** — every
repo must be gated individually before use.

## Fork record (org: [1243353366](https://github.com/1243353366))

Each fork preserves full upstream git history and carries a root `NOTICE`
file crediting the original author (handle + repo URL) and stating what changed.

| Fork | NOTICE commit | Changes made |
|---|---|---|
| [1243353366/gitleaks](https://github.com/1243353366/gitleaks) | `8b87ac4` | NOTICE added; integrated as isolated detect-only service (`services/investigate/exposure-scanner/`) |
| [1243353366/openedgar](https://github.com/1243353366/openedgar) | `b954321` | NOTICE added; integrated as isolated corporate-filings service (`services/investigate/corporate-filings/`) |
| [1243353366/sugartrail](https://github.com/1243353366/sugartrail) | `3f3925c` | NOTICE added; integration point reserved (`services/investigate/` — public-records adapter pending) |

Integration rule: **no direct merge of fork code into core reflexive-osint**.
Each fork runs as an isolated service behind the Investigate mode API boundary
until a human confirms license compatibility and code quality.

## Module A — Exposure Detection Layer (`services/exposure-scanner/`)

Source: gitleaks (MIT, forked). Serves Defend mode (secret/credential exposure
scanning) and Investigate mode (leaked credentials as an entity source).

- **HARD CONSTRAINT — detection-only.** No authentication, verification, or
  live calls using any discovered credential. No "verify this key works" step,
  ever, under any framing. Findings are flagged and reported, full stop.
- New entity type `ExposedSecret`, linked to `Organization` / `Repository` /
  `Bucket` nodes in the relationship graph.
- Output schema: finding reference, rule id, entropy score, redacted secret
  preview — never the full secret material.

## Module B — Corporate Relationship Graph (`services/corporate-filings/`)

Source: openEDGAR (MIT, forked). The core of the "follow them money, but
relationships instead of money" engine.

- Object model: `Company` / `Filing` / `Person` / `Subsidiary` from SEC EDGAR.
- Relationship edges: ownership chains, executive overlaps, subsidiary
  structure.
- Planned extensions — all public-record sources, no scraping behind auth
  walls: OpenCorporates, USPTO assignment records, FEC filings, GDELT.

## Module C — Threat Intel Enrichment (keep existing, extend)

Existing and retained: OTX, AbuseIPDB, Pulsedive, GDELT DOC API.

Additions (all public, documented free tiers):

- Shodan InternetDB (free, no key)
- VirusTotal public API
- NVD / CVE feed

**Rate-limit constraint:** stay within documented free-tier rate limits on all
of these. No circumventing rate limits via key rotation or proxying.

## Module D — Public Records Sourcing (`services/public-records/`)

Reference: [bellingcat toolkit org](https://github.com/bellingcat) — a
mixed-license org. Repos are selected per-source, individually gated at the
license step. `bellingcat/EDGAR` is GPL-3.0 and **excluded**. Current pick:
**sugartrail** (MIT) for companies/officers/addresses networks, complementing
openEDGAR for non-US corporate records. Additional vetted MIT sources as needs
arise: `name-variant-search`, `alias-generator`, `auto-archiver`.

## Attribution

See the Credits & Attribution section of the [README](../README.md) and
[CREDITS.md](../CREDITS.md). Upstream authors of forked code retain their
original licenses and copyright.

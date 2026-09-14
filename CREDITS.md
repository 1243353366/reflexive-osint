# Credits & Attributions

This repository is a conceptual research document, and it is openly derivative by design. The [Author's Note](docs/00-authors-note.md) states this plainly: the underlying concepts come from established work across cybersecurity, network telemetry, behavioral analytics, machine learning, OSINT, and privacy engineering. What is original here is the assembly, the extrapolation, and the self-audit — not the invention of these ideas.

This file credits the original authors and organizations whose work this document builds on. All code in this repository is original (AI-assisted, per the [README](README.md) disclosure); **no source code was copied from any of the projects below** — they are credited for ideas, terminology, and methods.

## Named individuals & organizations

| Original work | Author / Origin | How it's used here |
|---|---|---|
| Reflexive Control Theory | **Vladimir A. Lefebvre** (reflexive processes and second-order thinking) | Core theoretical backbone — modeling an adversary's model of you (`docs/06`) |
| Behavioral Game Theory; Level-k reasoning | **Colin F. Camerer** (*Behavioral Game Theory*, 2003) | Attribution filtering and evasion-complexity modeling (`docs/06`) |
| Quantal Response Equilibrium | **Richard McKelvey & Thomas Palfrey** | Probabilistic response modeling in the pipeline (`docs/06`) |
| ATT&CK framework & technique IDs (TA0042, TA0043, T1583, T1589, T1590, T1594, …) | **The MITRE Corporation** | Threat-taxonomy scaffolding for the counter-surveillance matrix (`docs/04`) |
| JA4 / JA4+ method — TLS & HTTP fingerprinting | **John Althouse** (JA4+ method series, 2023) | Transport-layer fingerprinting throughout (`docs/02`, `docs/04`, `docs/05`) |
| CanaryTokens | **Thinkst (Thinkst Canary)** | Canary-trap / bait-document mechanism (`docs/04`) |
| p0f — passive OS fingerprinting | **Michal Zalewski (lcamtuf)** | Kernel-trait fingerprinting concept (`docs/04`) |
| "UMBRAGE-style" techniques (reference) | CIA UMBRAGE project, as publicly disclosed (Vault 7) | Referenced as naming convention for low-level impersonation analysis (`docs/05`) |
| Honeypot / decoy architecture practice | The honeypot research community (incl. **The Honeynet Project**) | Web honey-pots and the "rabbit hole" decoy design (`docs/04`, `docs/05`) |

## Referenced technologies & libraries

The architecture references (but does not copy code from) these projects, each under its own license: PostgreSQL, TimescaleDB, PyTorch, PyTorch Lightning, PyTorch Geometric, scikit-learn, Hugging Face Transformers, Celery, Redis, NetworkX, Plotly / Dash, Prometheus / Grafana, the R ecosystem (tidyverse, text2vec, topicmodels, anomalize, DBI/RPostgres), nlohmann/json, libcurl, and Boost.

## General

Broad conceptual debts also extend to the fields of traffic analysis (timing, jitter, MTU/MSS analysis), differential privacy (Dwork et al.), Certificate Transparency monitoring, and WAF/bot-management practice — techniques this document assembles and pushes past their validated use cases.

**If any original author feels their work is credited inaccurately or insufficiently here, open an issue and it will be corrected.**

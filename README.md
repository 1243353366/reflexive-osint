# Reflexive-OSINT — Adversarial Behavioral Modeling Pipeline

> **This is a conceptual research document — not validated, not production software, and not operational tooling.**
> Every architectural claim in this repository is a hypothesis. The document concludes by auditing itself: see [**The Epistemic Autopsy**](docs/07-epistemic-autopsy.md) for which claims survive scrutiny, which are overstated, and what would falsify each one.

**What this is:** a conceptual, end-to-end pipeline that assembles established ideas from cybersecurity, network telemetry, behavioral analytics, machine learning, OSINT, and privacy engineering — then deliberately pushes them past their validated use cases and records what happens. As the [Author's Note](docs/00-authors-note.md) puts it: *"I didn't invent the ingredients. I just made the most cursed casserole possible and then audited the recipe."*

**What this is not:**

- **Not a working system.** Nothing here has been built, tested, calibrated, or deployed. Named modules are speculative architecture, not production code.
- **Not a guide for attacking, deanonymizing, or surveilling anyone.** All techniques are framed as *defensive* security measures.
- **Not established science.** Claims about identity attribution, intent, cognition, and geolocation are explicitly downgraded by the document's own audit. Treat them as research questions, not findings.

---

## Ethics & Scope

- **Defensive framing throughout.** Sections that read as aggressive — canary tokens, bait documents, honey-pots, active probing, decoy architectures — are labeled **Defensive** and exist as countermeasures for people who are being stalked, harassed, or actively surveilled. They are presented as what a *defender* does against an adversary already attacking them, never as stalking/attack tooling.
- **Legal boundaries are part of the document.** Part 04 contains an explicit legal analysis (entrapment, CFAA, GDPR/CCPA) and concludes that only passive, telemetry-based countermeasures are defensible — active or deceptive measures require legal review and are described **conceptually, not as recommendations**.
- **Privacy engineering is a first-class requirement.** The architecture calls for differential privacy, data minimization, retention limits, redaction, and human-in-the-loop review gates before any mitigation action.
- **Self-skepticism is the point.** The closing autopsy strips identity, cognition, intent, and geolocation claims entirely and rewrites every overconfident conclusion as a modest, context-bound statement.

---

## Repository Layout

The original single document, split into structured parts. Each part carries a **Status — Conceptual** label; defensive-scope parts carry a **Scope — Defensive** label.

| Part | File | Contents |
|---|---|---|
| 00 | [`docs/00-authors-note.md`](docs/00-authors-note.md) | Author's note on derivation, honesty, and limits |
| 01 | [`docs/01-pipeline-architecture.md`](docs/01-pipeline-architecture.md) | Full pipeline architecture: C++ ingestion, SQL/R cleaning, Python feature engineering, PyTorch modeling, orchestration, monitoring, and the 16-week roadmap |
| 02 | [`docs/02-plain-english-explainer.md`](docs/02-plain-english-explainer.md) | The whole system explained in plain English (network fingerprints, JA4, TLS handshakes, HTTP/2 lies) |
| 03 | [`docs/03-operational-framework.md`](docs/03-operational-framework.md) | Operational boundaries: differential privacy, temporal validation, edge inference, engineering metrics |
| 04 | [`docs/04-counter-stalking-defense.md`](docs/04-counter-stalking-defense.md) | **Defensive:** counter-surveillance against stalkers (MITRE TA0043/TA0042 countermeasures), the counter-stalking dashboard, and the legal analysis |
| 05 | [`docs/05-hardening-and-fingerprint-fixes.md`](docs/05-hardening-and-fingerprint-fixes.md) | **Defensive:** code hardening (deadlock, SQL injection, model poisoning fixes), protocol fingerprinting, jitter analysis, production containerization, decoy "rabbit hole" design |
| 06 | [`docs/06-theoretical-foundations.md`](docs/06-theoretical-foundations.md) | Theory: Lefebvre's reflexive control, Camerer's behavioral game theory, NLP pipeline optimization |
| 07 | [`docs/07-epistemic-autopsy.md`](docs/07-epistemic-autopsy.md) | The self-audit: plausible hypotheses vs. overstated claims vs. pure speculation, with falsification criteria for each |
| 08 | [`docs/08-investigate-mode-v2.md`](docs/08-investigate-mode-v2.md) | Investigate mode v2: OSINT aggregation + relationship graph — license gate record, fork provenance, isolated-service integration spec |

**Suggested reading order:** 00 → 01 → 02 → 07 (if you only read four things), then the rest.

---

## A Note on the Code

Code samples are **conceptual pseudocode-quality implementations** included to make the architecture concrete. They are intentionally illustrative — not hardened, not tested, and not safe to run against real systems without legal review and proper authorization.

## AI Disclosure

Yes, AI tools were used to help write and format the code and this repo. Every concept, design decision, and line of reasoning is mine — the AI was a keyboard, not a co-author. If you have a problem with that, you can fuck off, because the thinking was all me.

---

## Credits & Attribution

Investigate mode's OSINT aggregation architecture (multi-source
entity-relationship graph pattern) was inspired by
[Palantir-OSINT](https://github.com/JehanPatel/Palantir-OSINT) by
[@JehanPatel](https://github.com/JehanPatel). No code from that
repository has been directly incorporated; the design pattern was
independently reimplemented for this project.

## Credits & Attributions

This document is openly derivative — see [CREDITS.md](CREDITS.md) for the original authors whose work it builds on (Lefebvre, Camerer, MITRE, John Althouse's JA4+, Thinkst, and others). No source code was copied from any of their projects.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Chosen over MIT for its explicit patent grant — reasonable protection for security-adjacent research. All code here is original (AI-assisted, per the disclosure above); no GPL/AGPL-family source is included in this repository, so the permissive license applies cleanly.

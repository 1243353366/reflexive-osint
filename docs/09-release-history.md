# Part 09 — Release History: Why v1.0.0 Was Deleted

> This note exists so the removal of the `v1.0.0` release and tag is
> documented, deliberate, and unambiguous — not something anyone has to
> infer from a missing tag.

## What was removed

The GitHub **release** `v1.0.0 — Reflexive-OSINT: conceptual document,
structured edition` and its **tag** (pointing at commit `1cc6951`) were
deleted on 2026-09-14, immediately before publishing `v2.0.0`.

## Why

1. **v1.0.0 described a superseded state.** It tagged the repository as a
   standalone conceptual document — before the Investigate Mode v2 layer
   (license gate trail, forked upstreams, `services/investigate/` code)
   existed. Every asset it pointed to predates the current architecture.
2. **One release should mean "current."** Keeping v1.0.0 alongside v2.0.0
   would present two competing "latest" snapshots of what this repository
   is. The v2 release is the single, accurate picture; the old release
   would only mislead a first-time visitor.
3. **Nothing was lost.** Git history is untouched — commit `1cc6951` and
   the entire v1 lineage (Parts 00–07, CREDITS.md) remain in the history
   and on `main`, unchanged. Deleting a release/tag removes a label, not
   the content. The v1 conceptual document is still part of this
   repository; v2 *adds* the Investigate layer on top of it.

## What replaced it

[`v2.0.0`](https://github.com/1243353366/reflexive-osint/releases/tag/v2.0.0)
— tagged at the current `main`, covering both the conceptual core (Parts
00–07) and the Investigate Mode v2 layer, with the full license-gate and
attribution record. See the release notes and
[Part 08](08-investigate-mode-v2.md).

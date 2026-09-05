# Oneview — Receipt Viewer Design Spec (v1)

**Date:** 2026-08-22 · **Author:** core
**Consumers:** onedoor delivery · onewatch (canary) build · onetrace (forensics)
build — one skin each, implemented against this spec and the reference mockup
(`oneview.html`, shipped beside this file).
**Status:** Phase-B launch asset. Demo-grade, read-only. Product GUIs
(onedoor ND-018/ND-020 and successors) are explicitly out of scope.

## 1. What this is

One design system, three skins. Each repo gets a generator script that reads
its own **verified** store and emits a static HTML page rendering receipts in
the shared visual language. The receipt is the hero object on every screen —
a certificate, not a dashboard row.

## 2. The law (the X-11 of UIs)

**Every displayed value is read from a verified artifact.** The generator runs
the same verification the CLI runs and renders its output — it never re-derives
its own rendering, never re-computes a digest for display, never formats a
number differently from how the store carries it. If verification fails, the
page shows the failure state; it never shows the value. Sample or synthetic
data appearing anywhere is labelled in-frame.

## 3. Scope fence (hard)

- Static HTML + inline CSS/JS, generated from the store, opened from disk.
- Read-only. No backend, no auth, no network calls at view time.
- Live tail = tailing the append-only ledger and appending receipt rows.
  Nothing mutates; nothing polls a server; a file-watch or re-run regenerates.
- NO dashboards, charts-over-time, filters, search, or settings. Each request
  for one of these is declined by pointing at this line.

## 4. Tokens (authoritative; vendor this block verbatim)

```css
--ground:#0B0D10; --surface:#141820; --card:#171C25; --card-hi:#1B212C;
--border:#2A3140; --border-soft:#222836;
--ink:#E9ECF1; --muted:#8C96A5; --faint:#5E6875;
--seal:#D4A855;                   /* brand accent — never signals state   */
--ok:#46C08E;  --ok-bg:#10241d;  --ok-bd:#1f4d3a;   /* verified/unchanged */
--bad:#E25C6E; --bad-bg:#2a151b; --bad-bd:#5c2733;  /* changed/deny/fault */
font-sans: 'Archivo' (400/500/600/700), fallback system sans;
font-mono: 'IBM Plex Mono' (400/500/600), fallback ui-monospace;
```

Rules: semantic green/red never double as brand accent; seal gold never
signals state. Digits that must be trusted are mono with tabular-nums. Dark
is the committed single theme; ground painted explicitly.

## 5. Receipt-card anatomy (all three skins)

1. **Header** — kind label (uppercase, seal color), human title, right-aligned
   mono meta (id · timestamp · protocol/run tag).
2. **Verdict banner** — the loudest element: badge (mono, semantic color) +
   one-sentence plain-language why. Instrument named wherever a behavioural
   claim appears.
3. **Field grid** — label/value rows; labels uppercase faint, values 13.5px,
   machine values mono. Budget objects render as cell chips.
4. **Chain block** (surface tint) — full 64-char digests, never truncated;
   sequence + chain status; anchor status in seal color.
5. **Footer** — one-line re-derivation promise + the single action button
   ("Re-derive this receipt" / "Replay the attribution"), which runs the
   verifier and re-renders.

## 6. Per-skin content (from real stores)

- **onedoor** — a decision receipt (deny-with-budget is the demo hero: action,
  effect label, typed reason, seven-field budget object, params provenance),
  plus the live tail of recent decisions.
- **onewatch** — the change certificate: baseline identity, served model
  (recorded from response), model-identity vs behaviour verdicts side by side,
  instrument + band, chain back to the sealed baseline, anchor line. Tail =
  the morning certificates. The real C4 incident is the launch content.
- **onetrace** — the attribution trace: pipeline flow with the indicted stage
  highlighted, failed clause quoted verbatim with its re-derived truth value,
  stages-clean count, instrument pins, replay line. Until the experiment
  produces a real fault, any shown fault is hand-injected and labelled.

## 7. Delivery

Vendor the token block + this spec into each repo (digest-pinned, the
rederivable-manifest pattern). Each skin: one generator script + one test
that the page's every displayed digest/number matches the store (X-11 test),
one test that verification-failure renders the failure state. Cold-clone:
`python -m <pkg>.viewer` produces the page from a fresh clone's store.

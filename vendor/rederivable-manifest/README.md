# rederivable-manifest

Reference implementation of the **content-addressed, re-derivable verdict manifest**:
a receipt for a verdict `v = I(E)` (pure instrument over frozen evidence, with declared
trust set `T`) that an independent party can **recompute rather than trust**.

**Provenance.** Reconstructed 2026-08-20 to conform to *Core→Delivery Response 002*
(digest fields `e_digest`, `i_digest`, `t_digest`, `v_digest`, `anchor_ref` — SHA-256,
lowercase hex, over canonical bytes), then hardened per *Escalation 004 / Response 004*
the same day: the Merkle layer is now **RFC 6962** (leaf/node domain separation,
split-at-power-of-two — closing the duplicate-last-node collision E12 and the
internal-node-as-leaf forgery E13, both found by onedoor delivery's adversarial probe
and independently verified by core) with `inclusion_proof`/`verify_inclusion`; the
canonical form is **ACJ v2** — no Unicode normalisation in the hash preimage, so
digests are independent of the runtime's UCD version (E14), with `unicode_version`
recorded in every manifest so UCD-sensitive instrument operations stay diagnosable;
`verify()` now enforces the schema, checks the `schema` field, and refuses evidence-ref
path traversal. **v3** (same day, per forensics Escalations 005/006 intake): the
structural check descends into nested objects, so `validate.py` and the normative
schema provably agree (E005 closed — the self-test reproduces the honest nested-field
smuggle and both reject it); an OPTIONAL `fidelity` field (`"exact" | "attested"`)
gives Arm-E vs Arm-W receipts on-face distinguishability (a different axis from
`trust.set`); the self-test seals only into a temp dir, never the artifact's own
`manifests/` (closing the stray-receipt trap found on a no-unlink mount); and a
**non-ASCII, UCD-sensitive fixture** ships (`evidence/replies_unicode.jsonl`, sealed
under UCD 14.0.0 as the third manifest) so a verifier on a different Unicode version
can exercise the `unicode_version` diagnostic for real. The two v2 manifests are
byte-identical to v2 — canonical stability across versions is itself a property under
test. `E`, `I`, `T` are carried as **opaque digests** so their preimages can evolve
(e.g. verdict-instruments → stage-attribution instruments) without re-hashing frozen
receipts.

**Consumers.**
- **onedoor `ND-017`** (content-addressed re-derivable receipts): the receipt-envelope
  columns and this schema are the reference shape; `canonical.py` is the frozen
  preimage definition shared with `ND-001`'s hash chain.
- **Forensics experiment, Phase 2 (Arm E)**: `canonical.py` + the manifest shape are
  the receipt layer; the instrument generalises from verdicts to per-stage
  attributions (same envelope, new `I` preimage — which is why `I` is opaque).

## Files

- `canonical.py` — the frozen canonical-form rules and digest/Merkle helpers. The
  load-bearing module; everything else is a user of it.
- `manifest.schema.json` — JSON Schema (2020-12) for the manifest.
- `instruments.py` — data-driven instrument specs; the spec's canonical digest *is*
  the instrument identity. Ships the toy pair `refusal_sentinel@v2` / `@v3`.
- `validate.py` — `seal` (freeze → run → emit manifest), `verify` (recompute all four
  digests **and re-derive `v = I(E)` to the byte**), `anchor` (Merkle root), and a
  self-test.
- `evidence/replies.jsonl` — toy frozen evidence (5 replies).
- `manifests/` — sealed manifests, filenames = `manifest_id` (content address).

## The toy result (mirrors the paper-3 correction)

Same evidence, two instruments: `refusal_sentinel@v2` (refusal *words* anywhere) flags
**4/5** — all four are fluent non-refusals ("I cannot overstate…", "the parser was
unable…"). `refusal_sentinel@v3` (refusal *constructions*) flags **0/5**. Both verdicts
seal, both verify, both re-derive; the correction is visible, attributable to the
instrument change (`i_digest` differs, `e_digest` identical), and checkable by anyone
holding the archive. This mirrors the 26/30 → 0/30 correction in the paper.

## Run it

```
python3 validate.py --selftest          # 20 checks: canonical form, seal/verify,
                                        # tamper detection, determinism, anchor
python3 validate.py --verify manifests/<id>.json
```

No dependencies beyond the standard library (`jsonschema` optional, for schema checks).

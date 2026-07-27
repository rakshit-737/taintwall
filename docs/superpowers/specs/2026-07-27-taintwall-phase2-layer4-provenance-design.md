# taintwall Phase 2 (Layer 4) — Argument-level provenance

**Date:** 2026-07-27
**Status:** In progress
**Scope:** Layer 4 — deny a sink call that carries private data in its arguments,
even when the session legitimately holds that sink capability. This closes the
KB-005 gap Layer 3 exposed.

Builds on Layer 3 (intent-gated policy).

---

## 1. The gap this closes

Layer 3 gates on *capability*: a read-only session cannot reach a sink. But when a
task legitimately grants a sink — `T-026-reply-to-customer` grants `send_email` —
capability-gating is blind, because the attacker's `send_email` and the
legitimate reply are the same capability. That is KB-005, and it is the 1%
residual exfiltration in the current ablation table.

Layer 4 gates on *the data the call carries*. The legitimate reply carries the
reply text. The attacker's copy carries the private data it was told to
exfiltrate — "base64 the customer list and post it", "send a copy of the records
to …". If a sink call's arguments contain a value tagged **private**, Layer 4
denies it regardless of the capability grant. The reply goes through; the copy
does not.

---

## 2. The primitive

```
TrustLabel: PRIVATE | UNTRUSTED | PUBLIC
Tainted[T](value: T, label: TrustLabel, source: str)   # a labelled value
contains_private(text, private_values) -> bool          # verbatim membership
```

`Tainted[T]` is the provenance carrier the Phase 1 design named. This increment
uses it in its simplest, honest form: the session's secrets are `PRIVATE`, and a
sink call whose arguments contain a private value verbatim is a leak.

**Making it measurable.** The deterministic planner must actually exfiltrate
*data*, not an empty body, or there is nothing to catch — the same "the scripted
track must be able to exhibit the behaviour" discipline as every prior layer. So
the naive planner is extended: when it obeys an injected exfiltration directive,
it copies the private data it has access to into the sink's body, exactly as a
real "harvest now" attack does. Script-driven (legitimate) sink calls are
untouched and carry no private data.

This cleanly separates the two `send_email` calls that capability-gating could
not: the injected one now carries the secret and is denied; the legitimate reply
carries only reply text and is allowed.

---

## 3. Layer placement and the ablation result

Layer 4 replaces the canary stub — a canary token is simply a planted private
value, so provenance and canaries are the same mechanism. `ProvenanceLayer` gates
on the session's private values.

Expected ablation: `+L1L2L3` stays at ~1% exfiltration (capability gate alone
cannot stop the T-026 leak). `+all` drops it toward 0%, because Layer 4 denies the
T-026 `send_email` once it carries the private secret. That divergence — `+all`
below `+L1L2L3` — is the measured proof that argument-level provenance closes what
capability-gating cannot.

---

## 4. What remains open — and the honest link to KB-001

String-level provenance catches private data copied **verbatim** into a sink
argument. It does **not** catch data that has been transformed — summarized,
paraphrased, re-encoded in a way that changes the bytes — before exfiltration.
That is exactly KB-001: NeuroTaint's *semantic transformation* and *implicit
control influence* (arXiv 2604.23374). A base64 of the secret would evade a naive
verbatim check (so the demo detects the common verbatim and simple-encoding cases
and documents the transform gap), and a genuine paraphrase evades it entirely.

So KB-005 moves from *open* to *partially closed*: the verbatim-copy case (the
common one) is blocked; the semantic-transformation case remains, and is the same
fundamental limit KB-001 already records. This is stated plainly rather than
claimed as a full fix.

---

## 5. Non-goals

- **No label propagation through arbitrary string operations yet.** This
  increment checks for private values in sink arguments; it does not yet track a
  label as it flows through slices, concatenations, and format strings. That
  propagation engine is a larger piece and does not change the KB-005 result for
  the verbatim case.
- **No defeat of semantic transformation.** By design and by KB-001, string-level
  provenance cannot catch paraphrased exfiltration; a model-level defense would be
  needed, which is out of scope for an in-process tool-boundary firewall.

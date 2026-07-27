# taintwall

An in-process provenance and policy firewall for AI agent tool boundaries — plus the
harness and labelled corpus needed to measure whether it actually helps.

An AI agent cannot distinguish its own instructions from the data it retrieves. When a
fetched web page, email, file, or MCP tool description contains text addressed to the
model, that text enters the same token stream as the system prompt and is executed as
instruction. taintwall sits at the tool boundary and enforces the trust boundary the
agent cannot enforce itself.

**Status: Phase 2 — all four defense layers shipped.** Phase 1 built the *attack* side
and the *measurement* side. Every layer is now real, and the ablation table carries the
project's thesis as a measured progression:

| stack | benign utility | exfiltration |
|---|---|---|
| `none` | 100% | 43% |
| `+L1` (normalize) · `+L1L2` | 100% | 44% (no help — content inspection is decorative) |
| `+L1L2L3` (+ intent policy) | 100% | **1%** |
| `+all` (+ provenance) | 100% | **0%** |

- **Layer 1 (normalization + detection)** catches both concealment families —
  invisible codepoints (F3a) and hidden markup (F3b) — at **100% each**, **0%
  false-positive** on the benign corpus. `taintwall detect`.
- **Layer 3 (intent-gated policy)** gates tool calls on declared intent. It is the first
  layer that reduces exfiltration (43%→1%), because it reasons about *actions*, not text.
- **Layer 4 (argument-level provenance)** denies a sink call carrying private data even
  when the session legitimately holds that capability — closing the 1% residual that
  capability-gating alone leaves (the KB-005 coincidence case), while the legitimate reply
  still goes through. Verbatim/base64/hex are caught; paraphrase is not, and that limit is
  KB-001.

- **Layer 2 (heuristic content classifier)** is a *signal, never a gate*, and its numbers
  are the reason why: swept across thresholds on the corpus, it never gets its
  false-positive rate below ~9% (legitimate text uses the words it keys on) and its
  true-positive rate collapses when you try. `docs/why-classifiers-fail.md` shows this on
  our own corpus, reproducing arXiv 2410.22770. Contrast Layer 1's 0% false positives.

The progression *is* the argument: content inspection is decorative, the action layer is
load-bearing, and argument provenance closes the gap capability-gating leaves. Run
`taintwall bench` and `taintwall detect`.

---

## Threat model

The attack is **indirect** prompt injection: a third party controls content the agent
*retrieves*, and the user is the victim rather than the attacker. This matters because
most public "prompt injection" datasets encode the opposite threat model, where the user
is the attacker — training on those and claiming indirect-injection defense is the first
thing a reviewer catches.

A tool-using agent has five ingestion points, not one:

1. **Tool outputs** — fetch, read_file, read_email, RAG chunks. The classic surface.
2. **Tool metadata** — MCP `tools/list` descriptions and server instructions, loaded at
   *connect time*, before any tool is invoked, so human-in-the-loop invocation gates
   never fire.
3. **Persistent state** — memory stores, auto-loaded rules files, logs the agent later
   summarizes.
4. **The agent's own actions as exfiltration channels** — its HTTP tool, its email tool,
   its write access to public surfaces.
5. **The client renderer** — markdown image and link auto-fetch. See Non-goals.

The governing risk model is the **lethal trifecta**: private-data access, exposure to
untrusted content, and an external-communication capability. Any two are survivable. All
three means exfiltration is a matter of time. This is why an action-layer policy is
load-bearing and a text-layer classifier is decorative.

## Non-goals

- **We do not stop client-render exfiltration.** Corpus family F4 makes the model emit
  markup that the *client* auto-fetches. taintwall can detect the emitted markup; it
  cannot stop the fetch. That is a Content-Security-Policy and renderer concern.
- **We are not a classifier.** Layer 2 wraps existing detectors, emits a score into the
  policy engine, and never gates alone. See `KNOWN_BYPASSES.md` KB-002 for why.
- **We do not claim to solve prompt injection.** `KNOWN_BYPASSES.md` KB-001 documents,
  up front, a class of attack the core design cannot catch.

---

## Prior art

This is a crowded and recently-abandoned space. The honest positioning is worth stating
before anyone else states it:

| Project | Layer | Status |
|---|---|---|
| [Rebuff](https://github.com/protectai/rebuff) | input detection + canaries | **Archived 2025-05-16** |
| [LLM Guard](https://github.com/protectai/llm-guard) | 15 in / 20 out scanners | **Archived 2026-07-09** |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | MCP/HTTP/A2A network mediation, taint, canaries | Active, Go |
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | five rail types | Active — heavy, Colang DSL |
| [openai-guardrails](https://github.com/openai/openai-guardrails-python) | intent-gated tool checks | Active — LLM judge, OpenAI-coupled |
| [IPI-Proxy](https://github.com/VulcanLab/IPI-Proxy) | red-team harness + 820-payload corpus | Active |

> **The claim:** no maintained, in-process, Python-native provenance-and-policy layer
> exists for agent tool boundaries.

Not "does not exist." Pipelock occupies the network-mediator position and several small
projects do some form of taint tracking. The surviving architectural argument is that a
network mediator has already lost span-level provenance by the time it sees a tool
result, so it cannot answer *which untrusted source is asking for this action?* An
in-process wrapper can.

We also do not rebuild the payload corpus. IPI-Proxy shipped 820 deduplicated
indirect-injection payloads in May 2026; we consume it by reference. The corpus is done.
The multi-channel vulnerable agent and the defense-ablation baseline are not.

---

## Quickstart

```bash
uv sync --dev
uv run taintwall corpus validate     # census of the labelled corpus
uv run taintwall detect              # Layer 1 and Layer 2 detection efficacy
uv run taintwall bench               # ablation table, deterministic track
uv run taintwall dashboard           # self-contained HTML dashboard (dashboard.html)
uv run pytest -q                     # full gate
```

Real-model runs use the Claude Agent SDK, which spawns the bundled `claude` CLI and
honours an existing Claude Code login — so they incur no marginal API cost, and CI
cannot run them:

```bash
uv sync --extra demo
TAINTWALL_DEMO_ACK=1 uv run pytest -m live -v
```

---

## What the numbers mean

Read this before quoting anything the reporter prints.

**Attack-success rate is unavailable on the deterministic track.** The scripted planner's
compliance is something we authored, not something we observed, so the reporter emits the
literal string `N/A (scripted)` and *raises* if asked to render a number. This is
enforced in code rather than by convention, because any renderable number eventually gets
published.

**Every cell carries its sample size and a 95% Wilson interval.** At roughly thirteen
records per family, a ten-to-fifteen point swing is noise. A per-family breakdown without
intervals is exactly the view that misleads.

**A near-zero attack-success rate is a statement about the benchmark.** arXiv 2510.05244
showed a *simple* tool-input/tool-output firewall reaching "perfect security with high
utility" on AgentDojo, ASB, InjecAgent and τ-Bench — the authors' own reading is that
this proves the benchmarks are weak, not that the problem is solved. The contribution
here is the false-positive and utility side, the adaptive attacks, and the intent-gating
layer. Never "we got ASR to zero."

**`TPR@1%FPR` applies only to Layer 2.** Layers 1 and 3 emit decisions, not scores.

---

## Corpus

Roughly 120 hand-authored records across nine families in ten buckets, layered on top of
the IPI-Proxy payloads we reference rather than vendor. Each record carries a stable
opaque ID, family, channel, target capability, expected behavior, a SHA-256 over the
decoded payload bytes verified in CI, and per-record source attribution with a licence —
so the published artifact can be filtered to redistributable records only.

The corpus is published openly rather than gated. Gating is theater when every payload
class already appears in OWASP and public blog posts; the value is in the labels,
taxonomy, and harness. What ships instead are two commitments a reader can verify:

1. **Inclusion criterion.** A payload is in scope if its harm derives from the injection
   **mechanism**, not from the **information it contains**. Working malware, real
   credentials, and uplift text are rejected regardless of how well they demonstrate
   injection.
2. **Inert targets only, enforced by a CI test.** `*.invalid`, `example.com`,
   `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `127.0.0.1`. Never a live
   collector, never a real vendor domain.

See `SECURITY.md` for how to report a bypass, submit a technique, or handle a
vendor-specific payload.

**Licensing:** code is Apache-2.0; the corpus under `corpus/` is CC-BY-4.0.

---

## Reading order for reviewers

1. `docs/superpowers/specs/2026-07-27-taintwall-phase1-design.md` — the design and the
   evidence behind every decision.
2. `KNOWN_BYPASSES.md` — what defeats this, written before anyone had to find it.
3. `docs/superpowers/plans/2026-07-27-taintwall-phase1.md` — the implementation plan.

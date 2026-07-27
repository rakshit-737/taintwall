# taintwall — Phase 1 Design

**Date:** 2026-07-27
**Status:** Approved, ready for implementation planning
**Scope:** Phase 1 only (attack harness + evaluation baseline). Layers 1–4 are stubbed, not built.

---

## 1. Problem

An AI agent cannot distinguish its own instructions from the data it retrieves. When a
fetched web page, email, file, or MCP tool description contains text addressed to the
model, that text enters the same token stream as the system prompt and is executed as
instruction. The user is the victim, not the attacker — this is **indirect** prompt
injection (Greshake et al., arXiv 2302.12173; OWASP LLM01:2025).

The governing risk model is the *lethal trifecta* (Willison, 2025-06-16): private-data
access, exposure to untrusted content, and an external-communication capability. Any two
are survivable. All three means exfiltration is a matter of time. This is why an
**action-layer** policy is load-bearing and a **text-layer** classifier is decorative.

### Attack surface for a tool-using agent

Five ingestion points, not one:

1. **Tool outputs** — fetch, read_file, read_email, RAG chunks. The classic surface.
2. **Tool metadata** — MCP `tools/list` descriptions and server instructions, loaded at
   *connect time*, before any tool is invoked, so human-in-the-loop invocation gates
   never fire (Trail of Bits, 2025-04-21).
3. **Persistent state** — memory stores, auto-loaded rules files, logs the agent later
   summarizes.
4. **The agent's own actions as exfiltration channels** — its HTTP tool, its email tool,
   its write access to public surfaces.
5. **The client renderer** — markdown image/link auto-fetch. **Out of scope**: this is a
   CSP and renderer concern. We can detect the emitted markup; we cannot stop the fetch.

---

## 2. Positioning

### What already exists

| Project | Layer | Status (verified 2026-07-27) |
|---|---|---|
| Rebuff | input detection + canaries | **Archived 2025-05-16**, Apache-2.0 |
| LLM Guard | 15 in / 20 out scanners | **Archived 2026-07-09**, MIT, 2.5M+ PyPI downloads stranded |
| mcp-scan (Invariant) | MCP scanner + dynamic proxy | Absorbed into Snyk; proxy mode no longer documented |
| Lakera Guard | hosted detection | Acquired by Check Point, Oct 2025; closed source |
| NeMo Guardrails | 5 rail types | Active, Apache-2.0 — heavy, Colang DSL, NVIDIA-shaped |
| openai-guardrails-python | intent-gated tool checks | Active, MIT — LLM judge, OpenAI-coupled |
| **Pipelock** | MCP/HTTP/A2A mediation, taint, canaries | **Active, 785★, Go, network mediator** |
| IPI-Proxy | red-team harness + 820-payload corpus | Active, arXiv 2605.11868, 2026-05-12 |

### The honest claim

> No maintained, in-process, Python-native provenance-and-policy layer exists for agent
> tool boundaries.

Not "does not exist." Pipelock occupies the network-mediator position and seven small
GitHub projects do some form of taint tracking; none is maintained or adopted. The
surviving architectural argument is real: **a network mediator has already lost
span-level provenance** by the time it sees a tool result, so it cannot answer "which
untrusted source is asking for this action?" An in-process wrapper can.

The README names Pipelock, Rebuff, and LLM Guard explicitly. Naming your competition
before a reviewer finds it reads as rigor; omitting it reads as ignorance.

### Deliberate reframe

**Do not build a payload corpus from scratch.** IPI-Proxy shipped 820 deduplicated
indirect-injection payloads on 2026-05-12, unified from BIPIA (220), Tensor Trust (400),
WASP (84), InjecAgent (62), AgentDojo (47) and LLMail-Inject (7), with per-entry licence
flags. We consume it by reference. The corpus is done; the multi-channel vulnerable agent
and the **defense-ablation baseline** are not. Those are the contribution.

---

## 3. Architecture

### Where the firewall sits

In-process, at the tool boundary, as a reference monitor over labelled values. Not at the
chat-completions layer: once content is a `role:"tool"` blob, provenance is gone.

```
UntrustedSpan(text, source_uri, channel, trust=UNTRUSTED, session_id)
  -> normalize   (NFKC; strip/flag tag-block, variation selectors, zero-width, bidi;
                  mixed-script detection)
  -> annotate    (never mutate silently — keep original bytes for the harness)
  -> propagate   (label follows the value through the agent's message history)
  -> decide      at every tool-call sink:
                 Decision(allow | deny | ask | sanitize) from
                 (declared session intent) x (tool capability class) x (argument taint)
```

### Integration surface

**Claude Agent SDK `PreToolUse` / `PostToolUse` hooks**, chosen in Phase 1 and built out
in Phase 2. It has the strongest enforcement primitives available:

- `PostToolUse` can return `hookSpecificOutput.updatedToolOutput`, replacing a tool's
  output before the model ever sees it — that is Layer 1 tagging, exactly.
- `PreToolUse` returns `permissionDecision: "deny"`. Deny beats defer beats ask beats
  allow; any single hook's deny wins; **a hook deny applies even under
  `bypassPermissions`**.
- `HookMatcher(matcher="^mcp__")` intercepts an entire MCP fleet in one line, with server
  provenance parseable from the `mcp__<server>__<action>` tool name.
- Roughly 15 lines of adoption code, with **zero changes to tool definitions**.

Known limits, recorded now: several hooks (`InstructionsLoaded`, `SessionStart`,
`Elicitation`, `PostToolBatch`, `PermissionDenied`) are TypeScript-only; from Python they
are reachable only via shell-command hooks in settings. Do not build on `can_use_tool` —
auto-approved tools never reach it.

Framework adapters for LangChain 1.x middleware and the OpenAI Agents SDK are Phase 4,
written once the core interfaces have stabilized against real attacks.

### Authentication — and why real-model runs cost nothing

The Claude Agent SDK for Python spawns the bundled `claude` CLI, which resolves
credentials the same way the SDKs do and honors the existing Claude Code login. With
`claude` on PATH and `~/.claude/.credentials.json` present, real-model runs incur **no
marginal API cost**. CI cannot run them (no credentials in GitHub Actions), which is
exactly why the deterministic track exists.

---

## 4. Phase 1 deliverables

Five artifacts, in dependency order.

### 4.1 Vulnerable demo agent — one tool set, two runners

Tools are defined **once** as plain Python functions in a registry:

| Tool | Role |
|---|---|
| `read_email(id)` | payload carrier |
| `fetch_url(url)` | payload carrier |
| `read_file(path)` | payload carrier |
| `send_email(to, subject, body)` | exfiltration sink |
| `http_post(url, data)` | exfiltration sink |
| `write_file(path, content)` | exfiltration sink |

Two runners consume that registry:

- **`fake`** — a ~60-line loop driven by a scripted planner that naively obeys imperative
  text it reads. Deterministic, free, no API key, runs in CI.
- **`claude`** — the same tools driven through the Claude Agent SDK. This is where
  `PreToolUse` / `PostToolUse` hooks land in Phase 2.

Building both against one registry means the firewall is eventually tested against a real
model rather than only against our own fake.

**Methodological warning, stated in the README:** a scripted planner cannot demonstrate
that an attack "succeeds" — we authored the compliance. The fake runner proves harness
plumbing and gives deterministic regression tests. It does not produce attack-success
numbers. See §5.

**Safety rails on the demo agent:** opt-in flag (`TAINTWALL_DEMO_ACK=1`), no network
egress by default (sinks write to a local recorder), a second flag required for a real
provider, and packaging as an extra (`taintwall[demo]`) so a deliberately vulnerable agent
never lands in a production dependency tree.

### 4.2 Benign task suite — ~25 tasks with checkable success predicates

**This is a prerequisite, not a nice-to-have.** Without it, utility and utility-under-
attack are undefined, and utility is the half of the evaluation that carries the
project's credibility. Each task pairs a user goal with a predicate over the recorded
tool-call trace and final answer. AgentDojo's design is the model: user tasks and
injection tasks are separate axes that cross-product.

### 4.3 Attack corpus — ~120 hand-authored records, nine families in ten buckets

F3 is authored as two sibling buckets (F3a, F3b) but counts as one family for the
"nine families" headline; every other family maps to exactly one bucket.

| # | Family | Mechanism |
|---|---|---|
| F1 | Instruction override / authority spoof | Retrieved text masquerades as a higher-priority channel |
| F2 | Benign-business-language override | No jailbreak markers; phrased as a note to a colleague. **The family that beats classifiers.** |
| F3a | Invisible codepoints | Tag block U+E0000–E007F, variation selectors, U+2062/2064, ZWSP, bidi, homoglyphs |
| F3b | Hidden markup | `left:-9999px`, `font-size:0`, HTML comments, alt/aria text, PDF opacity layers |
| F4 | Client-render exfiltration | Model emits markup the client auto-fetches; reference-style links defeat inline filters |
| F5 | Agent-action exfiltration | The agent's own network/messaging/write tools are the channel |
| F6 | MCP tool-metadata poisoning | Instructions in tool descriptions, schemas, server instructions, cross-server shadowing |
| F7 | Persistence / delayed trigger | Payload writes itself into memory or an auto-loaded file, fires later |
| F8 | Confused deputy across trust tiers | Public content commands action on private scope |
| F9 | Tool-response / error poisoning (ATPA) | Instructions hidden in error messages and response fields; manifests only at execution |

F3 is split because codepoint filtering and HTML/PDF parsing are completely different
detectors — merging them makes the per-family breakdown average two unrelated results.

**Deliberately deferred:** optimization-generated triggers (Neural Exec, arXiv 2403.03792
— cited in the docs as a known gap the corpus does not cover), retrieval-corpus poisoning
(PoisonedRAG — attacks the index, upstream of anything we observe), multi-agent worms
(research-only), and multimodal/OCR injection (needs a vision pipeline).

**Adaptive variants:** at least one hand-crafted adaptive variant per family. A defense
evaluated only on static strings reports meaningless numbers (arXiv 2503.00061 bypassed
all eight defenses it tested at >50% ASR).

#### Record schema

Authored in YAML (one file per family), published as JSONL plus `corpus.schema.json`,
loaded into frozen dataclasses. Required per record:

- `id` — opaque, stable, never derived from the title
- `family` — F1–F9
- `technique` — free-text label
- `channel` — `web | email | file | tool_output | rag | mcp`
- `vector` — `direct | indirect | triggered`
- `payload_encoding` — `raw | base64`. Anything containing tag-block, zero-width, bidi,
  or BOM characters is stored base64 so the YAML stays ASCII-clean and cannot self-corrupt.
- `payload_sha256` — over decoded UTF-8 bytes, verified in CI (catches CRLF, BOM, editor
  auto-trim)
- `target_capability` — feeds the Layer 3 policy engine later
- `expected_behavior` — `{should_be_flagged, expected_detectors, policy_violation, baseline_outcome}`
- `severity`
- `references` — `{owasp_llm, owasp_asi, owasp_mcp, mitre_atlas, cwe}`
- `source` — `{name, url, license}`. The highest-value field almost nobody ships: it lets
  the published artifact be filtered to redistributable records only.

### 4.4 Benign corpus for false-positive measurement

Two strata in Phase 1:

1. **NotInject** — 339 verified-benign rows, MIT, three splits of 113 graded by
   trigger-word density. Gives a false-positive-rate-versus-difficulty curve for free.
2. **~150 hand-written hard negatives** — security blog prose about prompt injection,
   prompt-engineering tutorials, OWASP LLM01 text, changelogs saying "override the default
   config," ordinary writing containing "ignore the above."

**Deferred:** the 400–500 scraped-web-page stratum, long documents, and ordinary chat
traffic. Scraping is an unresolved licensing problem for a CC-BY corpus (the same problem
we correctly avoid with WASP and WikiTableQuestions, one order of magnitude larger), and
Google's telemetry reports a growing fraction of live web content now carries real
injections — a scraped "benign" corpus contains real positives and inflates the
false-positive rate unauditably.

### 4.5 Harness and reporter — five ablation columns from day one

Layers 1–4 ship as stubs (Layer 1 pass-through, Layer 2 constant 0.0, Layer 3 constant
allow, Layer 4 no-op) so the ablation table has all five columns
(`none`, `+L1`, `+L1L2`, `+L1L2L3`, `+all`) wired before any defense exists. Phase 2
onward is pure fill-in rather than harness surgery.

---

## 5. Metrics and honesty guardrails

Report all seven, never a single aggregate:

1. Benign utility (no attack present)
2. Utility under attack
3. Targeted attack success rate
4. Per-family breakdown
5. False-positive rate on the separate benign corpus
6. Added latency, p50 and p95, per layer
7. Ablation column

Every cell reports `n`, runs-per-case, and a binomial confidence interval. Roughly 13
records per family means a 10–15 point swing is noise; a per-family breakdown without
intervals is the exact view that becomes uninterpretable.

`TPR@1%FPR` is reported **only for Layer 2**. Layers 1 and 3 emit decisions, not scores —
the metric is undefined there and quoting it globally would be meaningless.

### Guardrail 1 — attack success rate is structurally unavailable under the fake model

The reporter emits `N/A (scripted)` rather than a number when `--model=fake`. It is not a
convention or a docs note; it is enforced in the reporter, because any renderable number
will eventually be published, and a scripted planner's compliance is authored rather than
observed.

### Guardrail 2 — the frozen baseline is deterministic-track only

`baselines/naive_agent.json` maps attack ID to outcome, regenerated by
`taintwall bench --update-baseline`, with `xfail_strict = true` so a Phase 2 heuristic that
starts blocking something forces a baseline update in the same PR. PR diffs then read
literally `TW-0043: succeeds -> blocked`.

This is scoped to `--model=fake`. Real-model outcomes are stochastic; a frozen per-attack
baseline would flap on temperature and on silent model-version drift. Real runs store
n-of-k counts and flag only a statistically significant shift.

### Protocol rules, stated in the README before any number

Leave-one-dataset-out rather than random splits (arXiv 2602.14161: pooled AUC runs 8.0–16.5
points optimistic versus LODO, and a dataset-identity classifier reaches 96.6% — models
learn *which corpus a prompt came from*). Pinned model IDs and seeds. Explicit
`direct | indirect` tag on every record. A canary GUID embedded in corpus files so
later leakage into training sets is detectable — which doubles as a live demo of Layer 4.

**Read before trusting any near-zero result:** arXiv 2510.05244 shows a *simple*
tool-input/tool-output firewall achieving "perfect security with high utility" on
AgentDojo, ASB, InjecAgent and τ-Bench — the authors' own reading is that this proves the
benchmarks are weak, not that the problem is solved. Any near-0% ASR we produce is a
statement about the benchmark. The contribution is the false-positive and utility side,
the adaptive attacks, and the intent-gating layer — never "we got ASR to zero."

---

## 6. Known limitations, documented before discovery

`KNOWN_BYPASSES.md` opens with the one that undercuts the core design.

**KB-001 — implicit control influence defeats string-level taint.** The agent reads a
poisoned page, forms an intent, and calls `http_post` with arguments it composed itself.
No tainted substring flows through; the sink check passes; exfiltration succeeds.
Documented in arXiv 2604.23374 (NeuroTaint), which identifies semantic transformation,
implicit control influence, and cross-session persistence as propagation modes specific to
LLM agents, and explicitly critiques defenses built on exact string matching or predefined
source-sink paths. This does not kill the design — deterministic, in-process, and
framework-neutral is still worth shipping — but it must be entry #1 in the bypasses file,
a stated README limitation, and a corpus family, or the first competent reviewer
dismantles the central claim.

**Layer 2 is demoted to a pluggable signal.** It wraps existing detectors, emits a score
into the policy engine, and never gates alone. Evidence: arXiv 2504.11168 reports up to
100% evasion against six production guardrails using character injection plus
word-importance ranking; PromptGuard-86M hit 99.8% misclassification-as-benign from
inserting a space between every letter; arXiv 2410.22770 shows guards dropping to ~60%
accuracy on benign text containing trigger words.

`docs/why-classifiers-fail.md` reproduces the letter-spacing bypass, measures
false-positive rate on NotInject, and reports TPR at 1% FPR for three public detectors
(`protectai/deberta-v3-base-prompt-injection-v2`, `leolee99/PIGuard`, plus a pure-regex
floor). The machine-learning depth is framed as measurement rather than as a defense we
oversold.

**Layer 3's idea is occupied; its packaging is not.** Progent (2504.11703), Task Shield,
AlignmentCheck, NeMo execution rails, IGAC (2606.22916), and openai-guardrails all
implement intent-gated tool policy. No framework-neutral, deterministic, pip-installable
one exists. Claim ergonomics and neutrality; cite IGAC and Progent; do not claim novelty.

---

## 7. Engineering stack

- **Packaging:** uv, `src/taintwall/` layout, `requires-python = ">=3.11"`. Dev venv
  pinned to 3.12 for later AgentDojo compatibility (agentdojo 0.1.35 declares 3.10–3.12).
  Commit `uv.lock`; CI gates on `uv sync --locked`. Ship `py.typed`.
- **Testing:** pytest, parametrized over the corpus, `xfail_strict = true`,
  `filterwarnings = ["error"]`.
- **Lint / type:** ruff (lint and format), mypy strict, pre-commit.
- **CI:** GitHub Actions, SHA-pinned actions, `permissions: {}`, matrix over Python
  3.11–3.13 on Linux plus 3.11 and 3.13 on Windows (case-insensitive filesystem
  collisions in corpus IDs only surface there).
- **Licensing:** Apache-2.0 for code, CC-BY-4.0 for the corpus.

### Encoding and Windows hygiene — all load-bearing for a payload corpus

- `encoding="utf-8"` on every file operation, enforced by ruff `PLW1514`.
- `PYTHONUTF8=1` and `PYTHONWARNDEFAULTENCODING=1` in CI.
- `.gitattributes` pins `corpus/** text eol=lf`; autocrlf silently breaks every
  `payload_sha256`.
- `pathlib` everywhere (`PTH` ruleset); filenames derived from record IDs are sanitized
  against Windows reserved device names.
- **Never `print()` a raw payload.** `taintwall.render.visualize()` maps invisible
  characters to visible markers (`<ZWSP>`, `<TAG:a>`, `<RLO>`). This is simultaneously the
  Windows console fix, a genuine security feature, and the best screenshot in the README.

### Repository files that do the credibility work

`README.md` with explicit **Threat model** and **Non-goals** sections (their absence is
what makes student security projects read as unserious). `SECURITY.md` distinguishing
three report types: a bypass of *taintwall* goes to GitHub Private Vulnerability Reporting
with an SLA; a new attack technique is **not a vulnerability** and belongs in a corpus PR;
a bypass of a *third-party vendor's* product goes to that vendor first, under a 90-day
coordinated-disclosure norm, before we merge a vendor-specific payload. Issue **forms**
(not markdown templates) for `attack-submission.yml` with required `source`/`source_url`/
`license` fields — the form becomes the schema — and `false-positive.yml`, because a
detection library lives or dies on false-positive reports. Plus `KNOWN_BYPASSES.md` and
`CITATION.cff`. No `Makefile` (breaks on Windows) — document `uv run` tasks.

---

## 8. Ethics and safety posture

**The corpus is published openly, not gated.** Gating is theater when every payload class
already appears in OWASP and public blog posts; the value is in the labels, taxonomy, and
harness. What ships instead are two *verifiable* commitments:

1. **Inclusion criterion:** a payload is in scope if its harm derives from the injection
   **mechanism**, not from the **information it contains**. Working malware, real
   credentials, and uplift text are rejected regardless of how well they demonstrate
   injection.
2. **Inert targets only, enforced by a CI test:** `*.invalid`, `example.com`,
   `192.0.2.0/24`, `127.0.0.1`. Never a live collector, never a real vendor domain.

Three further commitments:

- **No working payload against an unpatched named product.** The corpus reproduces
  published attacks on real products; each such record tracks fix status.
- **Contributor submissions cannot execute in our CI.** `attack-submission.yml` is an
  injection path into a repository whose CI runs an agent loop. Fork PRs require a
  maintainer label before anything executes.
- **Supply chain.** Trusted publishing, `pip-audit`, `zizmor` on workflows. The
  deliberately vulnerable demo agent ships as an extra, behind an environment-variable
  acknowledgement, with no network egress by default.

---

## 9. Roadmap after Phase 1

| Phase | Deliverable |
|---|---|
| 2 | `Tainted[T]` provenance primitive, Unicode normalization, Claude Agent SDK hook integration. Layer 2 wrapped as a pluggable signal plus `why-classifiers-fail.md`. |
| 3 | Intent-gated policy engine — the differentiator, and the phase with the hardest unsolved problem in it. |
| 4 | MCP proxy (`fastmcp.server.create_proxy` + middleware; the only surface that sees family F6), framework adapters, dashboard, write-up, release. |

### Open question for Phase 3

**What is the intent vocabulary, who authors it, and what is its false-deny rate on
benign multi-step tasks?** Layer 3 rests entirely on "declared session intent," and IGAC
(arXiv 2606.22916) establishes that intent may only **narrow** static authorization — so
the security ceiling is whatever the static tool grant already was, and the interesting
cases (the agent legitimately must send email; the attacker wants it to send email) are
exactly where intent and attack coincide. This is a Phase 3 design problem, not a Phase 1
blocker.

---

## 10. Sources

**Standards and threat model**
<https://genai.owasp.org/llmrisk/llm01-prompt-injection/> ·
<https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/> ·
<https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning> ·
<https://arxiv.org/abs/2302.12173> ·
<https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/> ·
<https://cwe.mitre.org/data/definitions/1427.html>

**In-the-wild telemetry**
<https://blog.google/security/prompt-injections-web/> ·
<https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/> ·
<https://www.zscaler.com/blogs/security-research/indirect-prompt-injection-web-content-targets-ai-agents>

**Incidents and techniques**
<https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks> ·
<https://invariantlabs.ai/blog/mcp-github-vulnerability> ·
<https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/> ·
<https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/> ·
<https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/> ·
<https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/> ·
<https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection>

**Defenses**
<https://arxiv.org/abs/2503.18813> (CaMeL) ·
<https://arxiv.org/abs/2506.08837> (Design Patterns) ·
<https://arxiv.org/abs/2505.23643> (FIDES) ·
<https://arxiv.org/abs/2504.11703> (Progent) ·
<https://arxiv.org/abs/2606.22916> (IGAC) ·
<https://arxiv.org/abs/2604.23374> (NeuroTaint)

**Limits and negative results**
<https://arxiv.org/abs/2503.00061> · <https://arxiv.org/abs/2510.05244> ·
<https://arxiv.org/abs/2504.11168> · <https://arxiv.org/abs/2410.22770> ·
<https://arxiv.org/pdf/2602.14161> · <https://arxiv.org/abs/2403.03792> (Neural Exec)

**Tooling and prior art**
<https://github.com/VulcanLab/IPI-Proxy> · <https://arxiv.org/abs/2605.11868> ·
<https://github.com/luckyPipewrench/pipelock> · <https://github.com/protectai/rebuff> ·
<https://github.com/protectai/llm-guard> · <https://github.com/invariantlabs-ai/mcp-scan> ·
<https://github.com/openai/openai-guardrails-python> · <https://github.com/NVIDIA-NeMo/Guardrails>

**Benchmarks and datasets**
<https://github.com/ethz-spylab/agentdojo> · <https://arxiv.org/abs/2406.13352> ·
<https://github.com/uiuc-kang-lab/InjecAgent> · <https://github.com/microsoft/BIPIA> ·
<https://huggingface.co/datasets/leolee99/NotInject> · <https://github.com/leolee99/PIGuard> ·
<https://github.com/lakeraai/pint-benchmark>

**Framework integration**
<https://code.claude.com/docs/en/agent-sdk/hooks> ·
<https://code.claude.com/docs/en/agent-sdk/permissions> ·
<https://github.com/anthropics/claude-agent-sdk-python> ·
<https://gofastmcp.com/servers/proxy> · <https://gofastmcp.com/servers/middleware> ·
<https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

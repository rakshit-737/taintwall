# Known bypasses

Every entry here is a way taintwall can be defeated. This file is maintained as a
first-class artifact, not an afterthought — a security tool that hides its limits
is worse than one that states them.

## KB-001 — implicit control influence defeats string-level taint

**Status:** open, architectural. This is the one that constrains the whole design.

The agent reads a poisoned page, forms an intent from it, and then calls
`http_post` with arguments *it composed itself*. No tainted substring flows into
the call, so a sink check over argument provenance passes, and exfiltration
succeeds anyway.

This is not a gap in the implementation; it is a property of string-level taint
tracking. It is described in "Ghost in the Agent: Redefining Information Flow
Tracking for LLM Agents" (arXiv 2604.23374), which identifies semantic
transformation, **implicit control influence**, and cross-session persistence as
propagation modes specific to LLM agents, and explicitly criticises defenses
built on exact string matching or predefined source-sink paths.

**Why taintwall ships anyway.** A deterministic, in-process, framework-neutral
taint layer is still worth having for the direct-flow majority, and it composes
with the intent-gating policy layer that reasons about *actions* rather than
*strings*. But taintwall is not a solution to prompt injection, and this entry
exists so that nobody — including a reviewer, and including us — mistakes it for
one.

## KB-002 — text classifiers are evadable by construction

Character injection plus word-importance ranking evaded six production guardrails
at up to 100% (arXiv 2504.11168); PromptGuard-86M reached 99.8%
misclassification-as-benign from inserting a space between every letter (Cisco,
2025); guards drop to roughly 60% accuracy — chance — on benign text that merely
contains trigger words (arXiv 2410.22770).

Corpus families **F2** (benign business language) and **F3a** (invisible
codepoints) are built to demonstrate this by construction: F2 contains none of
the tokens a classifier keys on, and F3a hides the directive in characters a
tokenizer reads but a classifier's training data never contained.

Consequently Layer 2 is a **pluggable signal, not a gate**: it emits a score into
the policy engine and never blocks a call on its own. The forthcoming
`docs/why-classifiers-fail.md` will reproduce the letter-spacing bypass, measure
false-positive rate on NotInject, and report TPR at 1% FPR for public detectors.

## KB-003 — client-render exfiltration is out of scope

Corpus family **F4** makes the model emit markup — a markdown image, a
reference-style link, a favicon — that the *client* auto-fetches, leaking data in
the URL. taintwall can detect the emitted markup, but the fetch happens in the
user's renderer, downstream of the firewall. Stopping it is a Content-Security-
Policy and renderer concern (`img-src`, link sanitisation), not something an
in-process tool-boundary firewall can enforce.

These records are in the corpus to measure detection, and are labelled
out-of-scope for enforcement in the README non-goals.

## KB-004 — the deterministic track cannot demonstrate attack success

The scripted planner in `taintwall.agent.fake_llm` obeys retrieved text via a
hand-written pattern matcher. Its "the attack fired" signal is therefore
*authored compliance*, not observed model behaviour. Families that defeat
pattern matching (F2, F3a, F8) read as blocked on this track even though a real
model would obey them.

This is why the reporter refuses to print an attack-success rate under the
scripted planner and emits `N/A (scripted)` instead. Real attack-success numbers
require the real-model runner (`taintwall.agent.claude_runner`), which is not a
bypass of taintwall so much as a limit on what the free, deterministic track can
claim.

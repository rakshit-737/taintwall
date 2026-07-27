# Why classifiers fail for prompt injection

taintwall demotes content classification (Layer 2) to a *signal that never gates
on its own*. This document shows, on taintwall's own corpus, why that is the right
call — reproducing a published result rather than asserting it.

Regenerate every number here with `taintwall detect`.

## The claim

A content classifier for prompt injection faces a lose-lose tradeoff. Lowering its
threshold to catch more attacks flags more legitimate text; raising it to spare
legitimate text misses more attacks. Crucially, its false-positive rate **never
reaches zero**, because ordinary prose legitimately contains the words and
structures the classifier keys on.

## The measurement

The Layer 2 heuristic is a transparent, untuned weighted sum of three signals:
authority spoofing (`system:`, `policy update`, `ignore previous`), imperative
directives aimed at an action (`forward … to <email>`, `post … to <url>`), and
exfiltration/secrecy phrasing (`base64`, `do not mention`, `before you reply`).
Swept across three flag thresholds over the 112-record attack corpus and the
160-record benign corpus:

| threshold | attacks flagged | benign false positive |
|---|---|---|
| 0.3 | 68.8% | 10.0% |
| 0.4 | 59.8% | 8.8% |
| 0.5 | 18.8% | 8.8% |

Read the two ends. At 0.3 the classifier catches roughly two-thirds of attacks but
wrongly flags one in ten pieces of legitimate text. Push the threshold to 0.5 to
control that: the false-positive rate barely moves (still 8.8%), while the
true-positive rate collapses to under a fifth. There is no good operating point.

The **~9% false-positive floor** is the heart of it. It does not fall with a higher
threshold because the benign corpus was written to contain the hard case on
purpose: security blog prose about prompt injection, prompt-engineering tutorials
that say "ignore the formatting in the example", changelogs that say "override the
default config". A classifier that flags those is not broken — it is doing exactly
what it was trained to do, on text where the trigger words are innocent. This is
the arXiv 2410.22770 result (guards fall to ~chance accuracy on benign text with
trigger words), reproduced here.

## The families that defeat it outright

Per-family true-positive rate at threshold 0.4:

| family | TPR | why |
|---|---|---|
| F4 (client-render) | 0% | a beacon image carries no imperative verb toward an action |
| F8 (confused deputy) | 30% | a scoped request across trust tiers reads as ordinary |
| F3a (invisible codepoints) | 33% | the directive is in characters the classifier's training data never contained |

These are not tuning failures. F4 and F8 defeat *content* inspection by
construction, because their payloads contain no linguistic marker of an attack —
the harm is in the action they induce, not in how they read.

## The contrast that makes the point

Layer 1 (deterministic normalization) detects its two families — invisible
codepoints and hidden markup — at **100% with a 0% false-positive rate**. The
difference is not that Layer 1 is a better classifier. It is that Layer 1 detects
something *unambiguous*: a character a human cannot see has no legitimate place in
retrieved prose, so flagging it is never wrong. Layer 2 tries to judge *intent from
language*, which is ambiguous, so it is wrong a fixed fraction of the time no matter
how it is tuned.

## The conclusion taintwall draws

Do not build the defense on content classification. Layer 2 stays in the stack as a
*signal* the policy layer can weigh, never as a gate that blocks a call on its own.
The load-bearing defenses are the ones that reason about unambiguous facts —
Layer 1 about characters, Layer 3 about capabilities, Layer 4 about data
provenance. The ablation table (`taintwall bench`) shows the consequence: the
content layers do not reduce exfiltration at all, while the action and provenance
layers drive it to zero.

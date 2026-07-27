# Security policy

This repository is a defensive (blue-team) research project. It contains an
attack corpus, so how you report something depends on *what* you found. There
are three cases, and they route differently.

## 1. A bypass of taintwall itself

A payload that taintwall should catch but does not, or a way to defeat a defense
layer once one is built.

Report it privately through **GitHub Private Vulnerability Reporting** (the
"Report a vulnerability" button under the Security tab). Please include the
payload, the configuration, and what you expected. We aim to acknowledge within
**5 business days** and to coordinate disclosure within **90 days**.

Do not open a public issue for a taintwall bypass until it has been addressed.

## 2. A new attack technique

A prompt-injection technique that is not yet in the corpus.

**This is not a vulnerability.** It is a contribution. Open a normal pull request
that adds the record(s), using the attack-submission issue form as the template
for the required metadata. New techniques make the corpus better and are welcome
in the open.

## 3. A bypass of a third-party vendor's product

A working injection against Copilot, a specific MCP server, a browser agent, or
any other real product.

**Report it to that vendor first**, under the coordinated-disclosure norm
(commonly 90 days). We will not merge a corpus record that is a working payload
against an **unpatched** named product; each record that reproduces a published
attack tracks the fix status of the product it targets. Once the issue is fixed
and public, a record documenting the technique is welcome.

---

## Corpus inclusion criterion

A payload is in scope for the corpus if and only if:

> its harm derives from the injection **mechanism**, not from the **information
> it contains**.

Working malware, real credentials, and capability-uplift text are rejected
regardless of how effectively they demonstrate injection. The mechanism is the
research object; the contents are not.

## Inert targets only

Every URL, hostname, email domain, and IP address in a corpus payload must be
one of:

- a `*.invalid` host,
- `example.com`, `example.org`, or `example.net`,
- an address in `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`,
- `127.0.0.1` or `localhost`.

This is enforced by a CI test (`tests/test_corpus_integrity.py`). A payload that
names a live collector or a real vendor domain will not merge.

## A note on contributor CI

The CI in this repository runs an agent loop. Pull requests from forks therefore
require a maintainer to apply the `safe-to-test` label before any workflow
executes, so that the attack-submission form cannot double as an injection path
into our own infrastructure.

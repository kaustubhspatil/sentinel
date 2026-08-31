# Security policy

## Supported versions

agentnorm is pre-1.0 with a single released version. Fixes land on the newest release;
there are no backports, and the honest advice is to upgrade.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no such release |

Python 3.10 and newer, per `requires-python`. Older interpreters are not tested and not
supported.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository.
That opens an advisory visible only to you and the maintainer.

Please do not open a public issue for a suspected vulnerability. Do not include real
customer data, credentials, or production audit records in a report — a minimal synthetic
reproduction is more useful anyway.

What to expect, from a single-maintainer project. These are realistic numbers rather than
flattering ones:

- **Acknowledgement within 7 days.**
- **An assessment within 21 days**, saying whether it is accepted and why.
- If accepted: a fix on the newest release, a GitHub Security Advisory, and credit in it
  unless you would rather not be named.
- If declined: the reasoning, in the same private thread. It stays private either way, and
  you are free to disclose on your own timeline.

## In scope

agentnorm parses traces, scores them, and writes audit records. A report is in scope if it
shows one of these:

- **Untrusted input compromises the host.** Code execution, path traversal, or unbounded
  resource consumption while parsing a trace, an OpenAPI specification, or an existing
  audit file.
- **Verification bypass.** `verify_chain()` reporting a chain intact after records have
  been modified, reordered, or removed. This is the security-critical function in the
  package.
- **Canonicalisation collision.** Two materially different records producing the same
  canonical bytes or the same hash. `canonical()` implements RFC 8785 for this domain and
  deliberately rejects floats rather than approximating their serialisation; a way around
  that rejection is in scope.
- **Data leakage.** Credentials, tokens, or personal data appearing in audit records or in
  `explain()` output that the caller did not put there.
- **A runtime dependency at module scope.** The package claims zero dependencies and a CI
  job walks the AST to enforce it. A way to defeat that check is a supply-chain issue.

## Not in scope

Two exclusions matter, and both are documented design limits rather than oversights.

**A detector missing an attack is not a vulnerability.** agentnorm is out-of-band detection
that never sits in the agent's request path; it cannot and does not claim to prevent
anything. The README states that union recall of 1.000 comes from generated anomalies and
is a ceiling, not a performance claim. Evasion findings are genuinely interesting — please
open a normal issue so they can be discussed in public, which is where that work belongs.

**Rewriting the whole audit file is not a vulnerability.** Hash chaining proves integrity,
not immutability: anyone who can rewrite the file can recompute the chain over their edits.
That is a property of the construction, stated in the documentation, and it is why
`chain_head()` exists — deployments anchor the head somewhere the writer cannot reach, such
as a WORM bucket or a transparency log. Reports that the chain can be forged *by a party
who can already rewrite the file* describe the documented model.

Also out of scope: findings that require an attacker who already controls the monitoring
host; automated scanner output with no demonstrated impact; and vulnerabilities in optional
integrations such as LangChain that are not reachable through agentnorm's own code.

## Properties worth knowing

- **Zero runtime dependencies**, enforced in CI. There is no transitive supply chain to
  audit. Optional adapters import their integration lazily, inside the function that needs
  it, so installing agentnorm pulls in nothing.
- **Out-of-band by construction.** It observes traces; it does not proxy, wrap, or gate the
  agent's calls. It cannot block a legitimate action, and it is not on the latency or
  availability path of the system it watches.
- **Audit records** are canonicalised per RFC 8785 and SHA-256 hash-chained.
  `verify_chain()` returns the index of the first broken record rather than a bare boolean,
  so a tampered log says *where*.

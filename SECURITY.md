# Security policy

Sentinel is a reference deployment and research repository, not a distributed package. It
is published so the method and the measurements can be inspected. **Do not run it as-is
against production infrastructure**; it is configured for a small demonstration estate.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository.
Please do not open a public issue. Expect acknowledgement within 7 days and an assessment
within 21.

Of most interest here:

- Committed secrets, credentials, tokens, or live host addresses. Anything of that kind is
  a mistake — report it and it will be rotated and purged rather than merely deleted.
- A generated MCP connector classifying a destructive or sensitive operation as safe, or
  deriving the wrong scope parameter for one. That misclassification propagates into the
  monitoring policy, so it is a real fault rather than a cosmetic one.
- Untrusted input compromising the host during parsing or indexing.

## Not in scope

Findings about the demonstration estate's own hardening — its firewall rules, its exposed
ports, its credentials — are out of scope. It is a disposable lab environment, currently
stopped, and it is not a claim about how anyone should configure a production fleet.

Detection limitations are not vulnerabilities. The README and `docs/detection.md` state
the measured limits directly, including where the numbers are ceilings produced by
generated data rather than performance claims. Findings that push on those limits are
welcome as ordinary issues.

## The library

Most of the security-relevant code now lives in the extracted library, which has its own
policy: [`packages/agentnorm/SECURITY.md`](packages/agentnorm/SECURITY.md).

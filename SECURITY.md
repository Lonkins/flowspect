# Security Policy

## Supported Versions

Only the latest release of flowspect receives security fixes.

## Reporting a Vulnerability

flowspect is a static analyzer — it never executes the flows it scans and needs no
credentials. Still, bugs in parsers handling untrusted export files are security-relevant.

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Lonkins/flowspect/security/advisories/new).
Do not open a public issue for an exploitable bug.

You can expect an acknowledgement within 7 days. Coordinated disclosure preferred;
we will credit reporters in the release notes unless you ask otherwise.

## Scope notes

- flowspect parses attacker-controllable files (flow exports). Parser crashes on
  malformed input are ordinary bugs; parser behavior that leads to code execution,
  path traversal, or resource exhaustion is in scope as a vulnerability.
- flowspect's YAML rule loading uses `yaml.safe_load` only. Any bypass of that is in scope.

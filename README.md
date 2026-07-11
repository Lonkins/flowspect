# flowspect

[![CI](https://github.com/Lonkins/flowspect/actions/workflows/ci.yml/badge.svg)](https://github.com/Lonkins/flowspect/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/flowspect)](https://pypi.org/project/flowspect/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)](https://pypi.org/project/flowspect/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**Static security analysis for visual agent-builder graphs.** Semgrep for agent flows:
flowspect imports exported projects from **Langflow, Dify, Flowise, and n8n**, normalises
them into a single graph IR, and runs taint analysis to find insecure data flows — before
they run in production.

```text
$ flowspect scan ./my-flow.json

  FS-TRIFECTA-001  critical  lethal trifecta: untrusted input reaches an
                             exfiltration sink while sensitive data is in scope
    path: Webhook → LLM Agent → HTTP Request
    fix:  gate the outbound request on validated output, or split the flow

  1 finding (1 critical) in 1 flow
```

## Why

Visual agent builders make it trivial to wire untrusted input (webhooks, chat, scraped
pages) into LLMs holding credentials and connected to tools that execute code, query
databases, and call the internet. Nothing reviews those wires. flowspect does — statically,
from the export file, in CI.

It finds things like:

- **Lethal trifecta** — untrusted input + sensitive data + an exfiltration channel in one flow
- **Prompt injection → execution** — user-controlled text reaching code/shell/SQL nodes unsanitised
- **Credential leakage** — secret-bearing nodes feeding outbound HTTP or messaging sinks
- **SSRF** — user input controlling fetch/HTTP request URLs
- **Unauthenticated webhooks** wired to state-changing actions
- and ~20 more — see the [rule catalog](https://lonkins.github.io/flowspect/rules/)

## Install

```bash
uv tool install flowspect   # or: pipx install flowspect / pip install flowspect
```

## Usage

```bash
flowspect scan ./exports/               # scan a directory of flow exports
flowspect scan flow.json --format json  # machine-readable output
flowspect scan flow.json --format sarif # GitHub code scanning
flowspect rules                         # list bundled rules
```

Every finding carries the exact node-to-node path through the graph and a remediation note.

### GitHub Action

```yaml
- uses: Lonkins/flowspect@v1
  with:
    paths: flows/
```

Uploads SARIF to GitHub code scanning so findings annotate PRs. See
[docs](https://lonkins.github.io/flowspect/github-action/).

### Custom rules

Rules are plain YAML — sources, sinks, sanitizers, and assertions over the graph:

```yaml
id: MY-RULE-001
severity: high
description: user input must not reach the shell node unsanitised
source: { capability: untrusted_input }
sink: { capability: code_execution }
sanitizer: { capability: output_validation }
```

See [writing your own rules](https://lonkins.github.io/flowspect/writing-rules/).

## Supported builders

| Builder  | Format            | Status |
|----------|-------------------|--------|
| Langflow | JSON export       | ✅     |
| Dify     | YAML DSL export   | ✅     |
| Flowise  | JSON export       | ✅     |
| n8n      | JSON export       | ✅     |

Version details in the [importer coverage matrix](https://lonkins.github.io/flowspect/importers/).

## What flowspect is not

Not an MCP tool-description scanner, not a runtime guardrail/proxy, not an observability
tool. It is static analysis of builder export files — it never executes your flows and
needs no API keys.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)

# flowspect

**Static security analysis for visual agent-builder graphs.** flowspect is
Semgrep for agent flows: it imports exported projects from **Langflow, Dify,
Flowise, and n8n**, normalises them into one graph IR, and runs taint analysis to
find insecure data flows — before they run in production. It never executes your
flows and needs no API keys.

```text
$ flowspect scan ./examples/vulnerable-langflow

  FS-INJECT-EXEC-001  critical  Prompt injection to code execution
    flow: Customer Chat → Compose Prompt → Support Agent → Python Tool
    fix:  Never let untrusted text reach a code/shell node directly.

  FS-TRIFECTA-001  critical  Lethal trifecta
    flow: Customer Chat → Compose Prompt → Support Agent → CRM Update
    fix:  Break one leg: gate the exfil sink, or drop the private-data source.

  7 findings (2 critical, 1 high, 4 medium) in 1 flow
```

## Why

Visual agent builders make it trivial to wire untrusted input (webhooks, chat,
scraped pages) into LLMs that hold credentials and drive tools which execute code,
query databases, and call the internet. Nothing reviews those wires. flowspect
does — statically, from the export file, in CI.

## What it catches

- **Lethal trifecta** — untrusted input + private data + an exfiltration channel in one flow
- **Prompt injection → execution** — untrusted text reaching code / shell / SQL nodes
- **Credential & data egress** — secret- or sensitive-bearing nodes feeding outbound HTTP or messaging
- **SSRF** and **second-order (indirect) injection** via fetched content
- **Unauthenticated webhooks** wired to state-changing actions
- …and more — see the [rule catalog](rules.md).

## How it works

1. An [importer](importers.md) maps a builder export onto the [Graph IR](ir.md) —
   typed, capability-tagged nodes and directed data-flow edges.
2. The [taint engine](engine.md) propagates taint from sources through the graph,
   stopped by sanitizers, into sinks.
3. [Rules](writing-rules.md) — authored in YAML — assert "no unsanitised path from
   source class X to sink class Y", plus structural node predicates.
4. Findings are rendered as a CLI report, JSON, or [SARIF](github-action.md) for
   GitHub code scanning — each carrying the exact node-to-node path and a fix.

Start with [installation](installation.md).

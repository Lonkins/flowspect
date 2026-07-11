# Importer coverage

Each importer maps a builder's native export onto the [Graph IR](ir.md). Importers
auto-detect format by file shape, so you never have to declare which builder a file
came from.

## Coverage matrix

| Builder  | Format            | Detected by                                   | Versions verified against |
|----------|-------------------|-----------------------------------------------|---------------------------|
| Langflow | JSON export       | top-level `data.{nodes,edges}`                | 1.x (incl. starter projects) |
| Dify     | YAML DSL export   | `app` + `kind: app`; `workflow` graph modes   | 0.x / 1.x (`workflow`, `advanced-chat`) |
| Flowise  | JSON export       | `nodes[].data.{name,category}`                | marketplace chatflows (2.x) |
| n8n      | JSON export       | top-level `nodes` + `connections`             | 1.x export / test workflows |

!!! note "Version policy"
    Builders evolve their export schemas. Importers are written against the fields
    that have been stable across the versions above and degrade gracefully:
    unknown component types map to no capability tags and act as taint
    pass-throughs, so a schema the importer doesn't fully understand makes
    flowspect quieter, never wrong.

## How capabilities are assigned

Importers translate builder-native component types into IR
[capability tags](ir.md#capabilities) — the vocabulary rules match on:

- **Langflow** — an exact component-type table (`ChatInput`, `PythonREPLTool`,
  `APIRequest`, …) plus substring families for the long tail (models, agents,
  search, vector stores, messaging). Inline `SecretStr` values become the `secrets`
  tag and are redacted from the IR.
- **Dify** — node `type` (`start`, `llm`, `code`, `http-request`,
  `knowledge-retrieval`, …) plus tool-provider ids for `tool` nodes.
- **Flowise** — `data.name` and `data.category`; inline credentials become `secrets`.
- **n8n** — the node-kind family (after `n8n-nodes-base.`); GET `httpRequest` is a
  fetch surface, non-GET an outbound sink; `ai_*` connections are tool bindings.

## Mapping tool bindings

Every builder draws an agent's tool as a `tool → agent` edge. Because the agent
controls the tool's arguments, taint reaching the agent must flow *back* into the
tool. Importers mark these edges as tool bindings (`EdgeKind.TOOL`) and the engine
traverses them in both directions — without this, prompt-injection→execution paths
would be invisible.

## Adding an importer

Implement the `Importer` protocol (`detect` + `load` returning a `Graph`), register
it in `flowspect.importers.REGISTRY`, and add a schema-faithful fixture. See
[CONTRIBUTING](https://github.com/Lonkins/flowspect/blob/main/CONTRIBUTING.md).

# Changelog

All notable changes to flowspect are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-07-11

First release. flowspect is a static security analyzer for visual agent-builder
graphs — "Semgrep for agent flows".

### Added

- **Graph IR** — capability-tagged nodes, ports, and directed data-flow edges
  (data + tool-binding kinds) with validated invariants.
- **Importers** for Langflow, Dify, Flowise, and n8n, each auto-detected and mapped
  to the IR; unknown components degrade to taint-transparent pass-throughs.
- **Taint engine** — reachability with forward data flow, bidirectional tool
  bindings, sanitizer neutralisation, loop termination, and shortest-path reporting.
- **Rule DSL** — YAML taint and structural rules with a node matcher, validated and
  compiled by the loader.
- **Bundled rule pack** — 27 rules covering the lethal trifecta, prompt-injection to
  code/SQL/deserialization/file-write/state-change, secret & sensitive-data egress,
  SSRF, second-order injection, unvalidated tool results, sub-flow boundary
  crossings, and structural checks (unauthenticated webhook, hardcoded secret,
  over-broad code/SQL tools, deserialization components).
- **Reporters** — rich terminal, JSON, and SARIF 2.1.0 (with per-node code flows and
  GitHub security-severity) for code scanning.
- **CLI** — `flowspect scan` and `flowspect rules`.
- **GitHub Action** and **pre-commit hook**, plus vulnerable/safe example projects.
- **Docs site** (MkDocs Material) with rule catalog, importer coverage matrix, IR
  reference, and a rule-authoring guide.

[Unreleased]: https://github.com/Lonkins/flowspect/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Lonkins/flowspect/releases/tag/v0.1.0

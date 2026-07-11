# GitHub Action

flowspect ships a composite action that scans your flow exports, uploads SARIF to
GitHub code scanning, and fails the job on findings.

## Quick start

```yaml
name: flowspect

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  flowspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Lonkins/flowspect@v1
        with:
          paths: flows/
          fail-on: high
```

Findings appear inline on pull requests and in the repository's **Security →
Code scanning** tab, each annotated with the full node-to-node flow.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | `.` | Space-separated files or directories to scan. |
| `version` | latest | flowspect version spec, e.g. `==0.1.0`. |
| `rules` | — | Extra rule file or directory. |
| `fail-on` | `low` | Minimum severity that fails the job. |
| `sarif-file` | `flowspect.sarif` | Where to write the SARIF report. |
| `upload-sarif` | `true` | Upload the SARIF to code scanning. |

## Notes

- The `security-events: write` permission is required for the SARIF upload. Without
  it, set `upload-sarif: false` and consume the artifact yourself.
- SARIF is emitted even when the job fails the threshold, so code scanning always
  reflects the latest state.
- flowspect makes no network calls and needs no secrets — the action only installs
  the package and runs the CLI.

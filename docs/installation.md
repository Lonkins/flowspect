# Installation

flowspect is a Python 3.12+ package with a single CLI entry point.

## From PyPI

```bash
uv tool install flowspect     # recommended — isolated tool install
# or
pipx install flowspect
# or
pip install flowspect
```

Verify:

```bash
flowspect --version
```

## From source

```bash
git clone https://github.com/Lonkins/flowspect
cd flowspect
uv sync            # creates .venv with runtime deps
uv run flowspect --version
```

## Pre-commit hook

Scan flow exports on every commit. Add to your repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Lonkins/flowspect
    rev: v0.1.0
    hooks:
      - id: flowspect
```

The hook scans changed JSON/YAML files and skips any that aren't recognised flow
exports, so it's safe to enable in a repo with mixed content.

## Requirements

flowspect needs no credentials and makes no network calls. It reads export files,
builds an in-memory graph, and reports. The only runtime dependencies are
`pydantic`, `typer`, `rich`, and `pyyaml`.

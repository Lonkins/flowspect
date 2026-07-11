# Contributing to flowspect

Thanks for helping make agent flows safer. This guide covers setup, workflow, and standards.

## Development setup

Requirements: [uv](https://docs.astral.sh/uv/) (manages Python 3.12 for you) and git.

```bash
git clone https://github.com/Lonkins/flowspect
cd flowspect
uv sync --all-extras          # creates .venv with all deps
uv run pre-commit install     # mandatory — CI runs the same hooks
uv run pytest                 # should pass before you start
```

## Workflow

1. Branch from `main` (`git checkout -b my-change`). `main` is protected; all changes land via PR.
2. Make atomic commits following [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
3. Every change ships with tests. New rules ship with true-positive **and** false-positive fixtures.
4. Push, open a PR, wait for CI (lint + types + tests + secret scan + build). Squash-merge.

Never use `--no-verify`. If a hook fails, fix the code.

## Standards

- **Typing:** `mypy --strict` clean. No `Any` escapes without a comment explaining why.
- **Lint/format:** ruff (config in `pyproject.toml`). Pre-commit auto-fixes most issues.
- **Tests:** pytest. Keep coverage high — new code paths need tests, especially
  taint-propagation edge cases (fan-in/out, loops, sub-flows).
- **No secrets:** gitleaks runs in pre-commit and CI over full history. Config/example
  files must contain placeholders only.

## Adding an importer

Implement the `Importer` protocol (`src/flowspect/importers/base.py`): `detect()` and
`load()` returning the Graph IR. Add real export fixtures under `tests/fixtures/<tool>/`
and update the coverage matrix in `docs/importers.md`.

## Adding a rule

Rules are YAML — see the [rule authoring guide](docs/writing-rules.md). Bundled rules live
in `src/flowspect/rules/builtin/` and require a fixture pair: one flow the rule must flag
(with the expected path) and one it must not.

## Reporting bugs

Use GitHub issues. For security bugs, see [SECURITY.md](SECURITY.md) — do not open a public issue.

# ADR 0001: Bootstrap decisions

Date: 2026-07-11 · Status: accepted

## Context

flowspect is built autonomously; design calls that would normally get review are recorded
here instead.

## Decisions

1. **Initial push contains hygiene + minimal skeleton, not hygiene alone.** CI cannot be
   green on a repo with no `pyproject.toml` (mypy/pytest/build all fail). The first two
   commits (hygiene files, then package skeleton + lockfile) were pushed together so `main`
   starts green. All subsequent work is PR-only behind branch protection.

2. **gitleaks runs as a direct CLI full-history scan, not `gitleaks-action`.** The action
   computes event-based commit ranges and crashes on the repository's root commit
   (`<root>^..` is an invalid revision). A pinned-binary `gitleaks git` scan of the full
   history is deterministic, event-independent, and equally free.

3. **Hand-rolled graph traversal instead of networkx.** The taint engine needs custom
   worklist propagation (taint sets per node, sanitizer stopping, loop fixpoint) that
   networkx does not provide; the only thing it would contribute is adjacency storage and
   BFS — a few dozen lines. Dropping it keeps the dependency tree at four runtime deps and
   avoids untyped-library friction under `mypy --strict`.

4. **Build backend: hatchling; env/deps: uv.** Boring, standard, well-supported src-layout
   packaging. `uv.lock` is committed for reproducible dev/CI environments.

5. **mypy runs as a pre-commit `local` hook (`uv run mypy`)** so it type-checks against the
   real resolved environment instead of a hermetic pre-commit venv without our dependencies.
   CI runs the identical hook set via `pre-commit run --all-files` — one source of truth.

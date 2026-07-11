# Releasing

flowspect releases are cut by tagging `vX.Y.Z`. CI builds, validates, and (once
enabled) publishes to PyPI.

## Steps

1. Bump `version` in `pyproject.toml` and `src/flowspect/__init__.py` (keep in sync).
2. Update `CHANGELOG.md` — move items under a new version heading, dated.
3. Regenerate the rule catalog if rules changed: `python scripts/gen_rule_catalog.py`.
4. Commit, merge to `main` via PR.
5. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.
6. Create the GitHub release from the tag with the changelog section as notes.

The `release` workflow (triggered by the tag) builds the sdist + wheel, runs
`twine check`, and verifies the tag matches the package version.

## PyPI publishing (one-time setup)

Publishing is **dormant by default** — the `publish-pypi` job is gated on the
`PYPI_ENABLED` repository variable. Publishing uses PyPI
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC), so **no API
token is ever stored in the repo**. To enable:

1. On [pypi.org](https://pypi.org), create the `flowspect` project (or reserve it)
   and add a **Trusted Publisher**:
   - Owner: `Lonkins`
   - Repository: `flowspect`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. Create a GitHub Actions **environment** named `pypi` (Settings → Environments).
3. Set the repository variable `PYPI_ENABLED=true` (Settings → Secrets and variables
   → Actions → Variables).

The next tagged release will publish automatically.

> Until step 3, tags still produce a green build with attached artifacts; the PyPI
> job is simply skipped. This is the intentional stopping point for an
> account/credential the automation cannot self-provision.

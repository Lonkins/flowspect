# Usage

## Scan

```bash
flowspect scan PATH [PATH ...] [options]
```

`PATH` is a flow export file or a directory. Directories are scanned recursively;
files that aren't recognisable flow exports are skipped.

```bash
flowspect scan flow.json                  # scan one file
flowspect scan ./flows/                    # scan a directory
flowspect scan a.json b.json ./more/       # multiple targets
```

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `--format`, `-f` | `table` | Output format: `table`, `json`, or `sarif`. |
| `--rules`, `-r` | — | Extra rule file or directory (added to the bundled pack). |
| `--builtin / --no-builtin` | `--builtin` | Include the bundled rule pack. |
| `--fail-on` | `low` | Minimum severity that makes the scan exit non-zero. |
| `--output`, `-o` | stdout | Write the report to a file. |
| `--skip-unrecognized`, `-s` | off | Skip named non-flow files instead of erroring (used by the pre-commit hook). |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on`. |
| `1` | Findings at or above `--fail-on`. |
| `2` | A rule failed to load. |

### Output formats

=== "table"

    Rich, human-readable report grouped by file. Each finding shows the severity,
    rule id, the node-to-node flow, and a remediation note.

=== "json"

    ```bash
    flowspect scan flow.json -f json -o report.json
    ```

    A summary plus every finding with its `path`, `path_labels`, `remediation`, and
    `references`. Good for custom tooling.

=== "sarif"

    ```bash
    flowspect scan flow.json -f sarif -o flowspect.sarif
    ```

    [SARIF 2.1.0](github-action.md) with a `codeFlows` entry naming every node on
    the tainted path. Upload it to GitHub code scanning.

## List rules

```bash
flowspect rules                 # bundled pack
flowspect rules -r my-rules/    # bundled + your own
```

## Tuning noise

- Raise `--fail-on` (e.g. `--fail-on high`) so only serious findings fail CI while
  lower-severity ones stay informational.
- Add a validation/guardrail node between a source and a sink: flowspect treats
  moderation, output-validation, and structured-output components as sanitizers and
  suppresses the flow.
- Author project-specific rules and pass them with `--rules`. See
  [Write your own rule](writing-rules.md).

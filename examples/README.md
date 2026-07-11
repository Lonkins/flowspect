# flowspect examples

Two intentionally-contrasting Langflow projects that drive the docs and tests.

| Project | What it shows |
|---------|---------------|
| [`vulnerable-langflow/`](vulnerable-langflow/) | Chat input reaches a Python tool (prompt-injection → execution) **and** a CRM webhook while private HR docs are in scope (lethal trifecta), plus a hardcoded API key. |
| [`safe-langflow/`](safe-langflow/) | The same flow secured: no code tool, replies gated through an output validator, private data replaced with a public FAQ. Reports **no findings**. |

Run them:

```bash
flowspect scan examples/vulnerable-langflow   # exits 1, reports findings
flowspect scan examples/safe-langflow         # exits 0, clean
```

[`flowspect-scan.yml`](flowspect-scan.yml) is a copy-paste GitHub Actions workflow
for scanning your own repo's flow exports and uploading results to code scanning.

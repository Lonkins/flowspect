"""Generate docs/rules.md from the bundled rule pack.

Run ``python scripts/gen_rule_catalog.py`` after changing rules. CI checks the
committed file matches (see tests/test_docs.py) so the catalog can't drift.
"""

from pathlib import Path

from flowspect.rules import load_builtin_rules
from flowspect.rules.schema import Rule, Severity

_HEADER = """\
# Rule catalog

flowspect ships {n} rules. Each is authored in the [rule DSL](writing-rules.md);
add your own with `--rules`. This page is generated from the bundled pack.

| Rule | Severity | Kind | What it finds |
|------|----------|------|---------------|"""

_SEV_BADGE = {
    Severity.CRITICAL: "🔴 critical",
    Severity.HIGH: "🟠 high",
    Severity.MEDIUM: "🟡 medium",
    Severity.LOW: "🔵 low",
}


def _row(rule: Rule) -> str:
    return f"| `{rule.id}` | {_SEV_BADGE[rule.severity]} | {rule.kind} | {rule.title} |"


def _detail(rule: Rule) -> str:
    lines = [f"### `{rule.id}` — {rule.title}", ""]
    lines.append(f"**Severity:** {rule.severity.value} · **Kind:** {rule.kind}")
    lines.append("")
    if rule.description:
        lines.append(" ".join(rule.description.split()))
        lines.append("")
    if rule.remediation:
        lines.append(f"**Remediation:** {' '.join(rule.remediation.split())}")
        lines.append("")
    if rule.references:
        refs = ", ".join(f"[{i + 1}]({url})" for i, url in enumerate(rule.references))
        lines.append(f"**References:** {refs}")
        lines.append("")
    return "\n".join(lines)


def render() -> str:
    rules = sorted(load_builtin_rules(), key=lambda r: (-r.severity.rank, r.id))
    parts = [_HEADER.format(n=len(rules))]
    parts.extend(_row(r) for r in rules)
    parts.append("\n## Rule details\n")
    parts.extend(_detail(r) for r in rules)
    return "\n".join(parts).rstrip() + "\n"


def output_path() -> Path:
    return Path(__file__).resolve().parent.parent / "docs" / "rules.md"


if __name__ == "__main__":
    output_path().write_text(render(), encoding="utf-8")
    print(f"wrote {output_path()}")

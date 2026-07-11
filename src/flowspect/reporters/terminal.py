"""Rich terminal reporter."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from flowspect.rules.schema import Severity
from flowspect.scanner import ScanResult

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render(result: ScanResult, console: Console) -> None:
    if result.errors:
        for err in result.errors:
            console.print(Text(f"⚠ {err.path}: {err.message}", style="yellow"))
        console.print()

    if not result.findings:
        console.print(
            Text(
                f"✓ No findings across {len(result.graphs)} flow(s).",
                style="bold green",
            )
        )
        return

    seen_first = False
    current_file: str | None = None
    for finding in result.findings:
        if not seen_first or finding.source_path != current_file:
            seen_first = True
            current_file = finding.source_path
            console.print()
            console.rule(Text(current_file or "(unknown file)", style="bold"))

        badge = Text(f" {finding.severity.value.upper()} ", style=_SEVERITY_STYLE[finding.severity])
        header = Text.assemble(badge, "  ", (finding.rule_id, "bold"), "  ", finding.title)

        body = Text()
        body.append("flow: ", style="dim")
        body.append(" → ".join(finding.path_labels))
        if finding.remediation:
            body.append("\nfix:  ", style="dim")
            body.append(finding.remediation.strip())
        if finding.references:
            body.append("\nref:  ", style="dim")
            body.append(finding.references[0], style="blue underline")

        console.print(Panel(body, title=header, title_align="left", border_style="dim"))

    _summary(result, console)


def _summary(result: ScanResult, console: Console) -> None:
    counts = result.counts()
    parts = [
        Text(f"{counts[sev]} {sev.value}", style=_SEVERITY_STYLE[sev])
        for sev in Severity
        if counts[sev]
    ]
    total = len(result.findings)
    line = Text(f"\n{total} finding(s) across {len(result.graphs)} flow(s):  ")
    for i, part in enumerate(parts):
        if i:
            line.append("  ")
        line.append_text(part)
    console.print(line)

"""flowspect command-line interface."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from flowspect import __version__
from flowspect.reporters import render, to_json, to_sarif
from flowspect.rules import RuleLoadError, load_builtin_rules, load_rules_dir, load_rules_file
from flowspect.rules.schema import Rule, Severity
from flowspect.scanner import scan_paths

app = typer.Typer(
    name="flowspect",
    help="Static security analysis for visual agent-builder graphs.",
    add_completion=False,
    no_args_is_help=True,
)


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"flowspect {__version__}")
        raise typer.Exit


@app.callback()
def _root(
    _version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """flowspect — find insecure data flows in agent-builder exports."""


def _load_rules(rules_path: Path | None, use_builtin: bool) -> list[Rule]:
    rules: list[Rule] = list(load_builtin_rules()) if use_builtin else []
    if rules_path is not None:
        extra = load_rules_dir(rules_path) if rules_path.is_dir() else load_rules_file(rules_path)
        rules.extend(extra)
    return rules


@app.command()
def scan(
    paths: Annotated[
        list[Path],
        typer.Argument(help="Flow export files or directories to scan.", show_default=False),
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    rules_path: Annotated[
        Path | None,
        typer.Option("--rules", "-r", help="Extra rule file or directory (adds to builtin)."),
    ] = None,
    use_builtin: Annotated[
        bool, typer.Option("--builtin/--no-builtin", help="Include the bundled rule pack.")
    ] = True,
    fail_on: Annotated[
        Severity,
        typer.Option("--fail-on", help="Minimum severity that makes the scan exit non-zero."),
    ] = Severity.LOW,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write report to a file instead of stdout."),
    ] = None,
    skip_unrecognized: Annotated[
        bool,
        typer.Option(
            "--skip-unrecognized",
            "-s",
            help="Skip named files no importer recognises instead of erroring (for hooks).",
        ),
    ] = False,
) -> None:
    """Scan flow exports for insecure data flows."""
    console = Console()
    err_console = Console(stderr=True)

    try:
        rules = _load_rules(rules_path, use_builtin)
    except RuleLoadError as exc:
        err_console.print(f"[red]Rule error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not rules:
        err_console.print("[yellow]No rules loaded (use --rules or drop --no-builtin).[/yellow]")

    result = scan_paths(paths, rules, skip_unrecognized=skip_unrecognized)

    if output_format is OutputFormat.JSON:
        _emit(to_json(result), output, console)
    elif output_format is OutputFormat.SARIF:
        _emit(to_sarif(result), output, console)
    else:
        render(result, console)

    worst = result.max_severity()
    if worst is not None and worst.rank >= fail_on.rank:
        raise typer.Exit(code=1)


@app.command(name="rules")
def list_rules(
    rules_path: Annotated[
        Path | None, typer.Option("--rules", "-r", help="Extra rule file or directory.")
    ] = None,
    use_builtin: Annotated[bool, typer.Option("--builtin/--no-builtin")] = True,
) -> None:
    """List loaded rules."""
    console = Console()
    try:
        rules = _load_rules(rules_path, use_builtin)
    except RuleLoadError as exc:
        Console(stderr=True).print(f"[red]Rule error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for rule in sorted(rules, key=lambda r: (-r.severity.rank, r.id)):
        console.print(
            f"[bold]{rule.id}[/bold]  "
            f"[dim]{rule.severity.value}[/dim]  "
            f"{rule.title}  [dim]({rule.kind})[/dim]"
        )
    console.print(f"\n[dim]{len(rules)} rule(s).[/dim]")


def _emit(text: str, output: Path | None, console: Console) -> None:
    if output is not None:
        output.write_text(text + "\n", encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output}")
    else:
        # print raw (no rich markup interpretation) so JSON/SARIF stay valid
        print(text)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

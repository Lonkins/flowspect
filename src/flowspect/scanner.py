"""Tie importers + analyzer together: scan files/directories, produce a result."""

from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from flowspect.analysis import Finding, analyze
from flowspect.importers import FlowParseError, import_file
from flowspect.ir import Graph
from flowspect.rules.schema import Rule, Severity

_FLOW_SUFFIXES = {".json", ".yml", ".yaml"}


class ScanError(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    message: str


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    findings: tuple[Finding, ...]
    scanned_files: tuple[str, ...]
    graphs: tuple[str, ...]  # "name (format)" per imported graph
    errors: tuple[ScanError, ...]

    def counts(self) -> dict[Severity, int]:
        out = dict.fromkeys(Severity, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)


def _iter_flow_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.suffix in _FLOW_SUFFIXES and p.is_file())
    return []


def scan_paths(
    paths: Iterable[Path], rules: Iterable[Rule], *, skip_unrecognized: bool = False
) -> ScanResult:
    """Import every flow file under the given paths and run the rules over each.

    A direct file that fails to parse is a reported error; a file discovered under
    a directory that is not a recognisable flow export is silently skipped (dirs
    routinely mix flow exports with unrelated JSON/YAML). With ``skip_unrecognized``
    a directly-named file that no importer recognises is skipped too rather than
    reported — the mode the pre-commit hook uses, since it is handed every changed
    JSON/YAML file regardless of whether it is a flow export.
    """
    rule_list = list(rules)
    findings: list[Finding] = []
    scanned: list[str] = []
    graph_ids: list[str] = []
    errors: list[ScanError] = []

    for root in paths:
        is_direct_file = root.is_file()
        if not root.exists():
            errors.append(ScanError(path=str(root), message="path does not exist"))
            continue
        for file in _iter_flow_files(root):
            report_errors = is_direct_file and not skip_unrecognized
            graph = _try_import(file, direct=report_errors, errors=errors)
            if graph is None:
                continue
            scanned.append(str(file))
            graph_ids.append(f"{graph.name} ({graph.source_format})")
            findings.extend(analyze(graph, rule_list))

    findings.sort(key=lambda f: (-f.severity.rank, f.source_path or "", f.rule_id, f.path))
    return ScanResult(
        findings=tuple(findings),
        scanned_files=tuple(scanned),
        graphs=tuple(graph_ids),
        errors=tuple(errors),
    )


def _try_import(file: Path, *, direct: bool, errors: list[ScanError]) -> Graph | None:
    try:
        return import_file(file)
    except FlowParseError as exc:
        # Only surface parse failures for files the user named directly; a stray
        # non-flow JSON inside a scanned directory is not an error worth reporting.
        if direct:
            errors.append(ScanError(path=str(file), message=str(exc)))
        return None

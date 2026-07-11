"""Importer registry and file-level entry points."""

from pathlib import Path

from flowspect.importers.base import (
    FlowParseError,
    Importer,
    UnsupportedFormatError,
    parse_file,
)
from flowspect.importers.dify import DifyImporter
from flowspect.importers.flowise import FlowiseImporter
from flowspect.importers.langflow import LangflowImporter
from flowspect.importers.n8n import N8nImporter
from flowspect.ir import Graph

# Order matters: more specific detectors first. Langflow and Flowise both use
# {nodes, edges}; Langflow nests under "data", Flowise nodes carry "category".
REGISTRY: tuple[Importer, ...] = (
    LangflowImporter(),
    DifyImporter(),
    N8nImporter(),
    FlowiseImporter(),
)

_FLOW_SUFFIXES = {".json", ".yml", ".yaml"}


def import_file(path: Path) -> Graph:
    """Parse one export file and map it to the IR via the first matching importer."""
    data = parse_file(path)
    for importer in REGISTRY:
        if importer.detect(data):
            return importer.load(data, source_path=str(path))
    raise UnsupportedFormatError(path, "no importer recognises this file")


def import_path(path: Path) -> list[Graph]:
    """Import a flow file, or every recognisable flow file under a directory.

    Unrecognisable files inside a directory are skipped (directories often mix
    flow exports with other JSON/YAML); a direct file path that fails raises.
    """
    if path.is_file():
        return [import_file(path)]
    if not path.is_dir():
        raise FlowParseError(path, "path does not exist")
    graphs: list[Graph] = []
    for candidate in sorted(path.rglob("*")):
        if candidate.suffix in _FLOW_SUFFIXES and candidate.is_file():
            try:
                graphs.append(import_file(candidate))
            except FlowParseError:
                continue
    return graphs


__all__ = [
    "REGISTRY",
    "FlowParseError",
    "Importer",
    "UnsupportedFormatError",
    "import_file",
    "import_path",
]

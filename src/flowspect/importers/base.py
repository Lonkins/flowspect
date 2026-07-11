"""Importer protocol and file dispatch.

Importers turn builder-native export files into the Graph IR. Each importer is
pluggable: implement the ``Importer`` protocol and add an instance to
``flowspect.importers.REGISTRY``.
"""

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

import yaml
from pydantic import JsonValue

from flowspect.ir import Graph


class FlowParseError(Exception):
    """The file could not be parsed or mapped to the IR."""

    def __init__(self, path: Path | None, message: str) -> None:
        self.path = path
        prefix = f"{path}: " if path else ""
        super().__init__(f"{prefix}{message}")


class UnsupportedFormatError(FlowParseError):
    """No registered importer recognises the file."""


@runtime_checkable
class Importer(Protocol):
    """A builder-specific loader producing the Graph IR."""

    format_name: str

    def detect(self, data: JsonValue) -> bool:
        """Cheaply decide whether ``data`` looks like this builder's export."""
        ...

    def load(self, data: JsonValue, *, source_path: str | None = None) -> Graph:
        """Map a detected export to the IR. Raises FlowParseError on malformed input."""
        ...


def parse_file(path: Path) -> JsonValue:
    """Parse a JSON or YAML export file into plain data."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FlowParseError(path, f"cannot read file: {exc}") from exc
    try:
        if path.suffix in {".yml", ".yaml"}:
            loaded: JsonValue = yaml.safe_load(text)
            return loaded
        parsed: JsonValue = json.loads(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise FlowParseError(path, f"not valid JSON/YAML: {exc}") from exc
    return parsed


def as_dict(value: JsonValue, *, path: Path | None = None) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise FlowParseError(path, f"expected a mapping, got {type(value).__name__}")
    return value


def as_list(value: JsonValue) -> list[JsonValue]:
    return value if isinstance(value, list) else []


def as_str(value: JsonValue, default: str = "") -> str:
    return value if isinstance(value, str) else default

"""Flowise JSON export importer.

Schema (verified against Flowise marketplace chatflows): top-level
``{"nodes": [...], "edges": [...]}``. Each node is
``{"id", "data": {"name", "label", "category", "inputs": {...}, "inputAnchors", "outputAnchors"}}``.
``data.name`` is the component id (e.g. ``chatOpenAI``, ``customFunction``); the
lowercased name plus ``category`` drive capability tagging. Edges carry composite
handles ``"<node>-output-..."`` / ``"<node>-input-<anchor>-<Types>"``.
"""

from pathlib import Path

from pydantic import JsonValue

from flowspect.importers.base import FlowParseError, as_dict, as_list, as_str
from flowspect.ir import Capability, Edge, EdgeKind, Graph, Node

# Matched against lowercased data.name (component id). First-substring wins are OR-ed.
_NAME_CAPS: tuple[tuple[str, frozenset[Capability]], ...] = (
    ("chattrigger", frozenset({Capability.UNTRUSTED_INPUT})),
    ("chatinput", frozenset({Capability.UNTRUSTED_INPUT})),
    ("apiloader", frozenset({Capability.WEB_FETCH, Capability.UNTRUSTED_INPUT})),
    ("customfunction", frozenset({Capability.CODE_EXECUTION})),
    ("codeinterpreter", frozenset({Capability.CODE_EXECUTION})),
    ("pythoninterpreter", frozenset({Capability.CODE_EXECUTION})),
    ("nodevm", frozenset({Capability.CODE_EXECUTION})),
    ("sqldatabase", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("sqlagent", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA, Capability.LLM})),
    ("postgres", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("mysql", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("requestsget", frozenset({Capability.WEB_FETCH})),
    ("requestspost", frozenset({Capability.OUTBOUND_HTTP})),
    ("httprequest", frozenset({Capability.OUTBOUND_HTTP})),
    ("webbrowser", frozenset({Capability.WEB_FETCH})),
    ("webscraper", frozenset({Capability.WEB_FETCH})),
    ("cheerio", frozenset({Capability.WEB_FETCH})),
    ("puppeteer", frozenset({Capability.WEB_FETCH})),
    ("playwright", frozenset({Capability.WEB_FETCH})),
    ("serpapi", frozenset({Capability.WEB_FETCH})),
    ("serper", frozenset({Capability.WEB_FETCH})),
    ("googlesearch", frozenset({Capability.WEB_FETCH})),
    ("searchapi", frozenset({Capability.WEB_FETCH})),
    ("bravesearch", frozenset({Capability.WEB_FETCH})),
    ("tavily", frozenset({Capability.WEB_FETCH})),
    ("readfile", frozenset({Capability.FILE_READ})),
    ("writefile", frozenset({Capability.FILE_WRITE})),
    ("gmail", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("slack", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("discord", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("telegram", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
)

# Matched against lowercased data.category (broader fallback).
_CATEGORY_CAPS: tuple[tuple[str, frozenset[Capability]], ...] = (
    ("chat models", frozenset({Capability.LLM})),
    ("llms", frozenset({Capability.LLM})),
    ("agents", frozenset({Capability.LLM})),
    ("memory", frozenset({Capability.MEMORY})),
    ("vector stores", frozenset({Capability.SENSITIVE_DATA})),
    ("document loaders", frozenset({Capability.SENSITIVE_DATA})),
)


def _capabilities(name: str, category: str, inputs: dict[str, JsonValue]) -> frozenset[Capability]:
    caps: set[Capability] = set()
    lname = name.lower()
    for needle, family in _NAME_CAPS:
        if needle in lname:
            caps |= family
    lcat = category.lower()
    for needle, family in _CATEGORY_CAPS:
        if needle in lcat:
            caps |= family
    # inline credentials embedded in the export
    if any(
        k.lower() in {"credential", "apikey", "password", "token"} and v for k, v in inputs.items()
    ):
        caps.add(Capability.SECRETS)
    return frozenset(caps)


class FlowiseImporter:
    format_name = "flowise"

    def detect(self, data: JsonValue) -> bool:
        if not isinstance(data, dict) or "nodes" not in data or "edges" not in data:
            return False
        nodes = data.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            return isinstance(data.get("edges"), list)
        first = nodes[0]
        if not isinstance(first, dict):
            return False
        node_data = first.get("data")
        # distinguish from langflow: flowise node.data has "name"+"category"
        return isinstance(node_data, dict) and (
            "category" in node_data or "inputAnchors" in node_data
        )

    def load(self, data: JsonValue, *, source_path: str | None = None) -> Graph:
        path = Path(source_path) if source_path else None
        top = as_dict(data, path=path)

        nodes: list[Node] = []
        kept_ids: set[str] = set()
        for raw in as_list(top.get("nodes")):
            if not isinstance(raw, dict):
                continue
            node_data = raw.get("data")
            if not isinstance(node_data, dict):
                continue
            node_id = as_str(raw.get("id")) or as_str(node_data.get("id"))
            if not node_id:
                raise FlowParseError(path, "flowise node without an id")
            name = as_str(node_data.get("name"))
            category = as_str(node_data.get("category"))
            inputs = node_data.get("inputs")
            inputs_dict = inputs if isinstance(inputs, dict) else {}
            scalar_inputs = {
                k: v
                for k, v in inputs_dict.items()
                if isinstance(v, str | int | float | bool) or v is None
            }
            nodes.append(
                Node(
                    id=node_id,
                    type=name or "unknown",
                    label=as_str(node_data.get("label")) or None,
                    capabilities=_capabilities(name, category, inputs_dict),
                    config=scalar_inputs,
                )
            )
            kept_ids.add(node_id)

        edges: list[Edge] = []
        for raw in as_list(top.get("edges")):
            if not isinstance(raw, dict):
                continue
            source = as_str(raw.get("source"))
            target = as_str(raw.get("target"))
            if source not in kept_ids or target not in kept_ids:
                continue
            target_handle = as_str(raw.get("targetHandle"))
            # tools/model/memory anchors bind capability providers into a chain/agent
            kind = EdgeKind.TOOL if "-input-tools-" in target_handle else EdgeKind.DATA
            edges.append(Edge(source=source, target=target, kind=kind))

        return Graph(
            name=as_str(top.get("name"), default="flowise chatflow"),
            source_format=self.format_name,
            source_path=source_path,
            nodes=tuple(nodes),
            edges=tuple(edges),
        )

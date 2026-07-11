"""Dify DSL (YAML) importer.

Schema (verified against Dify 0.x/1.x DSL exports): top-level
``{"app": {"name", "mode"}, "kind": "app", "workflow": {"graph": {"nodes", "edges"}}}``.
Graph-bearing modes are ``workflow`` and ``advanced-chat``; legacy ``chat`` /
``agent-chat`` / ``completion`` apps have no graph and are rejected with a clear
error. Node semantics live in ``node.data.type`` (start, llm, code,
http-request, tool, knowledge-retrieval, ...). Iteration/loop children appear in
the same node list (with ``parentId``), so the graph arrives pre-flattened.
"""

from pathlib import Path

from pydantic import JsonValue

from flowspect.importers.base import FlowParseError, as_dict, as_list, as_str
from flowspect.ir import Capability, Edge, Graph, Node

_TYPE_CAPS: dict[str, frozenset[Capability]] = {
    "start": frozenset({Capability.UNTRUSTED_INPUT}),
    "llm": frozenset({Capability.LLM}),
    "agent": frozenset({Capability.LLM}),
    "question-classifier": frozenset({Capability.LLM}),
    "parameter-extractor": frozenset({Capability.LLM}),
    "knowledge-retrieval": frozenset({Capability.SENSITIVE_DATA}),
    "http-request": frozenset({Capability.OUTBOUND_HTTP}),
    "code": frozenset({Capability.CODE_EXECUTION}),
    # end/answer/if-else/iteration/template-transform/variable-* are pass-throughs
}

# Dify tool nodes carry provider ids like "google", "tavily", "slack" …
_TOOL_PROVIDER_CAPS: tuple[tuple[str, frozenset[Capability]], ...] = (
    ("google", frozenset({Capability.WEB_FETCH})),
    ("bing", frozenset({Capability.WEB_FETCH})),
    ("duckduckgo", frozenset({Capability.WEB_FETCH})),
    ("tavily", frozenset({Capability.WEB_FETCH})),
    ("searxng", frozenset({Capability.WEB_FETCH})),
    ("serper", frozenset({Capability.WEB_FETCH})),
    ("crawl", frozenset({Capability.WEB_FETCH})),
    ("scrape", frozenset({Capability.WEB_FETCH})),
    ("jina", frozenset({Capability.WEB_FETCH})),
    ("firecrawl", frozenset({Capability.WEB_FETCH})),
    ("webscraper", frozenset({Capability.WEB_FETCH})),
    ("wikipedia", frozenset({Capability.WEB_FETCH})),
    ("slack", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("discord", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("telegram", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("wecom", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("dingtalk", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("email", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("smtp", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("gmail", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("twilio", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("github", frozenset({Capability.STATE_CHANGE})),
    ("sql", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("database", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("code_interpreter", frozenset({Capability.CODE_EXECUTION})),
    ("vanna", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
)

_GRAPH_MODES = {"workflow", "advanced-chat"}


def _tool_capabilities(data: dict[str, JsonValue]) -> frozenset[Capability]:
    haystack = " ".join(
        as_str(data.get(key)).lower()
        for key in ("provider_id", "provider_name", "tool_name", "tool_label")
    )
    caps: set[Capability] = set()
    for needle, family in _TOOL_PROVIDER_CAPS:
        if needle in haystack:
            caps |= family
    return frozenset(caps)


def _scalar_config(data: dict[str, JsonValue]) -> dict[str, JsonValue]:
    skip = {"selected", "desc", "title", "type"}
    return {
        k: v
        for k, v in data.items()
        if k not in skip and (isinstance(v, str | int | float | bool) or v is None)
    }


class DifyImporter:
    format_name = "dify"

    def detect(self, data: JsonValue) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("app"), dict)
            and (data.get("kind") == "app" or "workflow" in data)
        )

    def load(self, data: JsonValue, *, source_path: str | None = None) -> Graph:
        path = Path(source_path) if source_path else None
        top = as_dict(data, path=path)
        app = as_dict(top.get("app"), path=path)
        mode = as_str(app.get("mode"))
        workflow = top.get("workflow")
        if mode not in _GRAPH_MODES or not isinstance(workflow, dict):
            raise FlowParseError(
                path,
                f"dify app mode {mode or 'unknown'!r} has no workflow graph; "
                "only 'workflow' and 'advanced-chat' apps are supported",
            )
        graph = as_dict(workflow.get("graph"), path=path)

        nodes: list[Node] = []
        kept_ids: set[str] = set()
        for raw in as_list(graph.get("nodes")):
            if not isinstance(raw, dict):
                continue
            node_data = raw.get("data")
            if not isinstance(node_data, dict):
                continue
            node_id = as_str(raw.get("id"))
            node_type = as_str(node_data.get("type"))
            if not node_id or not node_type:
                continue  # decorative nodes (custom-note) have no semantic type
            caps = _TYPE_CAPS.get(node_type, frozenset())
            if node_type == "tool":
                caps = caps | _tool_capabilities(node_data)
            nodes.append(
                Node(
                    id=node_id,
                    type=node_type,
                    label=as_str(node_data.get("title")) or None,
                    capabilities=caps,
                    config=_scalar_config(node_data),
                )
            )
            kept_ids.add(node_id)

        edges: list[Edge] = []
        for raw in as_list(graph.get("edges")):
            if not isinstance(raw, dict):
                continue
            source = as_str(raw.get("source"))
            target = as_str(raw.get("target"))
            if source not in kept_ids or target not in kept_ids:
                continue
            source_handle = as_str(raw.get("sourceHandle"))
            edges.append(
                Edge(
                    source=source,
                    target=target,
                    # "source"/"target" are react-flow defaults, not real ports;
                    # if-else branches export "true"/"false" handles worth keeping
                    source_port=source_handle if source_handle not in {"source", ""} else None,
                    target_port=None,
                )
            )

        return Graph(
            name=as_str(app.get("name"), default="dify app"),
            source_format=self.format_name,
            source_path=source_path,
            nodes=tuple(nodes),
            edges=tuple(edges),
        )

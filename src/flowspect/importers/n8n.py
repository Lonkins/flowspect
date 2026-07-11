"""n8n workflow JSON importer.

Schema (verified against n8n export/test workflows): top-level
``{"nodes": [...], "connections": {...}}``. Nodes are
``{"name", "type": "n8n-nodes-base.<kind>", "parameters": {...}}``; n8n wires by
node **name**, not id: ``connections[srcName]["main"][outIdx] = [{"node": tgtName,
"type": "main", "index": inIdx}, ...]``. We key IR nodes by name for stable edges.
"""

from pathlib import Path

from pydantic import JsonValue

from flowspect.importers.base import FlowParseError, as_dict, as_list, as_str
from flowspect.ir import Capability, Edge, EdgeKind, Graph, Node

# Matched against the node "kind" (the part after "n8n-nodes-base." / "@n8n/..."),
# lowercased. n8n has 400+ node types; we tag the security-relevant families.
_KIND_CAPS: tuple[tuple[str, frozenset[Capability]], ...] = (
    ("webhook", frozenset({Capability.UNTRUSTED_INPUT, Capability.STATE_CHANGE})),
    ("formtrigger", frozenset({Capability.UNTRUSTED_INPUT})),
    ("chattrigger", frozenset({Capability.UNTRUSTED_INPUT})),
    ("emailtrigger", frozenset({Capability.UNTRUSTED_INPUT})),
    ("emailreadimap", frozenset({Capability.UNTRUSTED_INPUT})),
    ("code", frozenset({Capability.CODE_EXECUTION})),
    ("function", frozenset({Capability.CODE_EXECUTION})),
    ("executecommand", frozenset({Capability.CODE_EXECUTION})),
    ("ssh", frozenset({Capability.CODE_EXECUTION})),
    ("httprequest", frozenset({Capability.OUTBOUND_HTTP})),
    ("webhookresponse", frozenset()),
    ("respondtowebhook", frozenset()),
    ("graphql", frozenset({Capability.OUTBOUND_HTTP})),
    ("postgres", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("mysql", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("microsoftsql", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("snowflake", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("questdb", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("cratedb", frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA})),
    ("mongodb", frozenset({Capability.SENSITIVE_DATA, Capability.STATE_CHANGE})),
    ("redis", frozenset({Capability.SENSITIVE_DATA})),
    ("readbinaryfile", frozenset({Capability.FILE_READ})),
    ("readpdf", frozenset({Capability.FILE_READ})),
    ("writebinaryfile", frozenset({Capability.FILE_WRITE})),
    ("gmail", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("emailsend", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("sendemail", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("slack", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("discord", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("telegram", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("twilio", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("mattermost", frozenset({Capability.MESSAGING, Capability.STATE_CHANGE})),
    ("executeworkflow", frozenset({Capability.SUBFLOW})),
    ("agent", frozenset({Capability.LLM})),
    ("openai", frozenset({Capability.LLM})),
    ("lmchat", frozenset({Capability.LLM})),
    ("chainllm", frozenset({Capability.LLM})),
    ("httprequesttool", frozenset({Capability.OUTBOUND_HTTP})),
)


def _kind(node_type: str) -> str:
    return node_type.rsplit(".", 1)[-1].lower() if node_type else ""


def _capabilities(node_type: str, parameters: dict[str, JsonValue]) -> frozenset[Capability]:
    kind = _kind(node_type)
    caps: set[Capability] = set()
    for needle, family in _KIND_CAPS:
        if needle in kind:
            caps |= family
    # Non-GET HTTP requests are outbound sinks; GET is a fetch surface (SSRF).
    if "httprequest" in kind:
        method = as_str(parameters.get("method"), default="GET").upper()
        if method == "GET":
            caps = (caps - {Capability.OUTBOUND_HTTP}) | {Capability.WEB_FETCH}
    return frozenset(caps)


def _scalar_params(parameters: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        k: v for k, v in parameters.items() if isinstance(v, str | int | float | bool) or v is None
    }


class N8nImporter:
    format_name = "n8n"

    def detect(self, data: JsonValue) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("nodes"), list)
            and isinstance(data.get("connections"), dict)
        )

    def load(self, data: JsonValue, *, source_path: str | None = None) -> Graph:
        path = Path(source_path) if source_path else None
        top = as_dict(data, path=path)

        nodes: list[Node] = []
        names: set[str] = set()
        for raw in as_list(top.get("nodes")):
            if not isinstance(raw, dict):
                continue
            name = as_str(raw.get("name"))
            if not name:
                raise FlowParseError(path, "n8n node without a name")
            if name in names:
                raise FlowParseError(path, f"duplicate n8n node name: {name!r}")
            node_type = as_str(raw.get("type"))
            params = raw.get("parameters")
            params_dict = params if isinstance(params, dict) else {}
            nodes.append(
                Node(
                    id=name,
                    type=node_type or "unknown",
                    label=name,
                    capabilities=_capabilities(node_type, params_dict),
                    config=_scalar_params(params_dict),
                )
            )
            names.add(name)

        edges: list[Edge] = []
        connections = as_dict(top.get("connections"), path=path)
        for src_name, outputs in connections.items():
            if src_name not in names or not isinstance(outputs, dict):
                continue
            for handle, streams in outputs.items():
                for stream in as_list(streams):
                    for link in as_list(stream):
                        if not isinstance(link, dict):
                            continue
                        tgt = as_str(link.get("node"))
                        if tgt not in names:
                            continue
                        # n8n AI nodes (ai_tool/ai_languageModel/ai_memory) wire
                        # provider->agent, same reversed binding as other builders.
                        kind = EdgeKind.TOOL if handle.startswith("ai_") else EdgeKind.DATA
                        edges.append(
                            Edge(
                                source=src_name,
                                target=tgt,
                                source_port=handle if handle != "main" else None,
                                kind=kind,
                            )
                        )

        return Graph(
            name=as_str(top.get("name"), default="n8n workflow"),
            source_format=self.format_name,
            source_path=source_path,
            nodes=tuple(nodes),
            edges=tuple(edges),
        )

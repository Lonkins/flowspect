"""Langflow JSON export importer.

Schema (verified against Langflow 1.x exports, incl. bundled starter projects):
top-level ``{"name", "data": {"nodes": [...], "edges": [...]}}``. Each node is
``{"id", "data": {"type", "display_name", "node": {"template": {field: {...}}}}}``;
sticky notes appear as nodes with type ``note``/``noteNode`` and are skipped.
Edges carry handles: ``data.sourceHandle.name`` / ``data.targetHandle.fieldName``.
"""

from pathlib import Path

from pydantic import JsonValue

from flowspect.importers.base import FlowParseError, as_dict, as_list, as_str
from flowspect.ir import Capability, Edge, Graph, Node

# Exact component-type → capabilities. Unknown types get no tags and act as
# taint pass-throughs, so omissions make flowspect quieter, never wrong-er.
_TYPE_CAPS: dict[str, frozenset[Capability]] = {
    "ChatInput": frozenset({Capability.UNTRUSTED_INPUT}),
    "Webhook": frozenset({Capability.UNTRUSTED_INPUT}),
    "TextInput": frozenset({Capability.TRUSTED_INPUT}),
    "APIRequest": frozenset({Capability.OUTBOUND_HTTP}),
    "SaveToFile": frozenset({Capability.FILE_WRITE}),
    "File": frozenset({Capability.FILE_READ, Capability.SENSITIVE_DATA}),
    "Directory": frozenset({Capability.FILE_READ, Capability.SENSITIVE_DATA}),
    "RunFlow": frozenset({Capability.SUBFLOW}),
    "SubFlow": frozenset({Capability.SUBFLOW}),
    "FlowTool": frozenset({Capability.SUBFLOW}),
    "PythonREPL": frozenset({Capability.CODE_EXECUTION}),
    "PythonREPLTool": frozenset({Capability.CODE_EXECUTION}),
    "PythonFunction": frozenset({Capability.CODE_EXECUTION}),
    "PythonCodeStructuredTool": frozenset({Capability.CODE_EXECUTION}),
    "ExecQuery": frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA}),
    "SQLExecutor": frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA}),
    "SQLDatabase": frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA}),
    "SQLAgent": frozenset({Capability.SQL_EXECUTION, Capability.SENSITIVE_DATA, Capability.LLM}),
}

# Substring families (checked lowercase) for the long tail of components.
_FAMILY_CAPS: tuple[tuple[str, frozenset[Capability]], ...] = (
    ("model", frozenset({Capability.LLM})),
    ("agent", frozenset({Capability.LLM})),
    ("memory", frozenset({Capability.MEMORY})),
    ("url", frozenset({Capability.WEB_FETCH})),
    ("websearch", frozenset({Capability.WEB_FETCH})),
    ("search", frozenset({Capability.WEB_FETCH})),
    ("wikipedia", frozenset({Capability.WEB_FETCH})),
    ("scrape", frozenset({Capability.WEB_FETCH})),
    ("email", frozenset({Capability.MESSAGING})),
    ("gmail", frozenset({Capability.MESSAGING})),
    ("slack", frozenset({Capability.MESSAGING})),
    ("discord", frozenset({Capability.MESSAGING})),
    ("telegram", frozenset({Capability.MESSAGING})),
    ("twilio", frozenset({Capability.MESSAGING})),
)

_VECTOR_STORES = (
    "astradb",
    "cassandra",
    "chroma",
    "clickhouse",
    "couchbase",
    "elasticsearch",
    "faiss",
    "milvus",
    "mongodb",
    "opensearch",
    "pgvector",
    "pinecone",
    "qdrant",
    "redis",
    "supabase",
    "upstash",
    "vectara",
    "weaviate",
)

_SKIP_TYPES = {"note", "noteNode", "Note"}


def _capabilities(component_type: str, config: dict[str, JsonValue]) -> frozenset[Capability]:
    caps = set(_TYPE_CAPS.get(component_type, frozenset()))
    lowered = component_type.lower()
    if component_type not in _TYPE_CAPS:
        for needle, family in _FAMILY_CAPS:
            if needle in lowered:
                caps |= family
        if any(store in lowered for store in _VECTOR_STORES):
            caps |= {Capability.SENSITIVE_DATA}
    if config.get("__has_secret_value__"):
        caps.add(Capability.SECRETS)
    return frozenset(caps)


def _flatten_template(template: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Reduce Langflow's template ``{field: {value, type, ...}}`` to ``{field: value}``.

    Adds ``__has_secret_value__`` when a SecretStr-typed field carries an inline
    value — a hardcoded credential in the export itself.
    """
    config: dict[str, JsonValue] = {}
    has_secret = False
    for field_name, field in template.items():
        if field_name == "_type" or not isinstance(field, dict):
            continue
        value = field.get("value")
        field_type = field.get("_input_type") or field.get("type")
        if field_type in {"SecretStr", "SecretStrInput"} and isinstance(value, str) and value:
            has_secret = True
            config[field_name] = "***"  # never carry the secret into the IR
            continue
        if isinstance(value, str | int | float | bool) or value is None:
            config[field_name] = value
    if has_secret:
        config["__has_secret_value__"] = True
    return config


class LangflowImporter:
    format_name = "langflow"

    def detect(self, data: JsonValue) -> bool:
        if not isinstance(data, dict):
            return False
        inner = data.get("data")
        return isinstance(inner, dict) and "nodes" in inner and "edges" in inner

    def load(self, data: JsonValue, *, source_path: str | None = None) -> Graph:
        path = Path(source_path) if source_path else None
        top = as_dict(data, path=path)
        inner = as_dict(top.get("data"), path=path)

        nodes: list[Node] = []
        kept_ids: set[str] = set()
        for raw in as_list(inner.get("nodes")):
            if not isinstance(raw, dict):
                continue
            node_data = raw.get("data")
            if not isinstance(node_data, dict):
                continue
            component_type = as_str(node_data.get("type"))
            if not component_type or component_type in _SKIP_TYPES:
                continue
            node_id = as_str(raw.get("id")) or as_str(node_data.get("id"))
            if not node_id:
                raise FlowParseError(path, "langflow node without an id")
            spec = node_data.get("node")
            template = as_dict(spec.get("template"), path=path) if isinstance(spec, dict) else {}
            config = _flatten_template(template)
            nodes.append(
                Node(
                    id=node_id,
                    type=component_type,
                    label=as_str(node_data.get("display_name")) or None,
                    capabilities=_capabilities(component_type, config),
                    config={k: v for k, v in config.items() if k != "__has_secret_value__"},
                )
            )
            kept_ids.add(node_id)

        edges: list[Edge] = []
        for raw in as_list(inner.get("edges")):
            if not isinstance(raw, dict):
                continue
            source = as_str(raw.get("source"))
            target = as_str(raw.get("target"))
            if source not in kept_ids or target not in kept_ids:
                continue  # edges touching skipped nodes (e.g. notes)
            handles = raw.get("data") if isinstance(raw.get("data"), dict) else {}
            source_port: str | None = None
            target_port: str | None = None
            if isinstance(handles, dict):
                sh = handles.get("sourceHandle")
                th = handles.get("targetHandle")
                if isinstance(sh, dict):
                    source_port = as_str(sh.get("name")) or None
                if isinstance(th, dict):
                    target_port = as_str(th.get("fieldName")) or None
            edges.append(
                Edge(source=source, target=target, source_port=source_port, target_port=target_port)
            )

        return Graph(
            name=as_str(top.get("name"), default="langflow flow"),
            source_format=self.format_name,
            source_path=source_path,
            nodes=tuple(nodes),
            edges=tuple(edges),
        )

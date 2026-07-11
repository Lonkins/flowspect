"""Graph IR — the single normalized representation every importer targets.

A flow is a directed graph of typed nodes. Importers map builder-native components
onto nodes carrying *capability tags*; rules and the taint engine operate purely on
this IR and never see builder-specific formats.
"""

from collections.abc import Mapping
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, JsonValue, model_validator


class Capability(StrEnum):
    """Semantic tags describing what a node can do or hold.

    Importers assign these from component-type mappings; rules match on them.
    """

    # Data origins
    UNTRUSTED_INPUT = "untrusted_input"  # webhooks, chat, public forms, inbound messages
    TRUSTED_INPUT = "trusted_input"  # operator-provided constants, scheduled triggers
    WEB_FETCH = "web_fetch"  # fetch/scrape nodes: SSRF surface + untrusted content
    SENSITIVE_DATA = "sensitive_data"  # vector stores, DB reads, private files/documents
    SECRETS = "secrets"  # nodes holding credentials, API keys, tokens

    # Processing
    LLM = "llm"  # LLM / agent nodes (follow instructions in data)
    MEMORY = "memory"  # conversation / long-term memory
    SUBFLOW = "subflow"  # opaque reference to another workflow

    # Dangerous effects (sinks)
    CODE_EXECUTION = "code_execution"  # python/js/shell execution
    SQL_EXECUTION = "sql_execution"  # SQL against a live database
    OUTBOUND_HTTP = "outbound_http"  # arbitrary outbound HTTP (exfil + SSRF)
    MESSAGING = "messaging"  # email/slack/telegram/etc. send (exfil channel)
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    STATE_CHANGE = "state_change"  # DB writes, CRUD calls, anything with side effects
    DESERIALIZATION = "deserialization"  # pickle/eval-style unsafe loading

    # Mitigations
    INPUT_VALIDATION = "input_validation"  # moderation, schema/allowlist checks on input
    OUTPUT_VALIDATION = "output_validation"  # guardrails/validators on model or tool output
    AUTHENTICATION = "authentication"  # the node's entry point requires auth


class Port(BaseModel):
    """A declared input or output connection point on a node."""

    model_config = ConfigDict(frozen=True)

    name: str
    dtype: str | None = None


class Node(BaseModel):
    """One component instance in a flow."""

    model_config = ConfigDict(frozen=True)

    id: str
    type: str  # builder-native component type, e.g. "Webhook", "PythonREPL"
    label: str | None = None  # user-visible display name
    capabilities: frozenset[Capability] = frozenset()
    inputs: tuple[Port, ...] = ()
    outputs: tuple[Port, ...] = ()
    config: Mapping[str, JsonValue] = {}  # normalized component settings, for structural rules

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities

    @property
    def display(self) -> str:
        return self.label or self.type


class EdgeKind(StrEnum):
    """How data moves along an edge.

    DATA: ordinary forward data flow (source's output feeds target's input).
    TOOL: a tool *binding* — source is a tool attached to an agent (target).
    Tool results flow forward, but the agent also controls the tool's
    arguments, so taint reaching the agent flows *backwards* into the tool.
    Every builder draws this edge tool→agent; the engine must treat it as
    bidirectional or it misses prompt-injection→execution entirely.
    """

    DATA = "data"
    TOOL = "tool"


class Edge(BaseModel):
    """A directed data-flow connection between two nodes."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    source_port: str | None = None
    target_port: str | None = None
    kind: EdgeKind = EdgeKind.DATA


class Graph(BaseModel):
    """A complete flow: nodes plus directed data-flow edges.

    Invariants (enforced on construction):
    - node ids are unique
    - every edge endpoint references an existing node
    - declared edge ports exist on their node *if* that node declares any ports
      (importers may omit port declarations; then any port name is accepted)
    """

    model_config = ConfigDict(frozen=True)

    name: str
    source_format: str  # "langflow" | "dify" | "flowise" | "n8n" | "ir"
    source_path: str | None = None
    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()

    @model_validator(mode="after")
    def _check_invariants(self) -> "Graph":
        ids = [n.id for n in self.nodes]
        id_set = set(ids)
        if len(ids) != len(id_set):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate node ids: {dupes}")
        by_id = {n.id: n for n in self.nodes}
        for e in self.edges:
            for endpoint in (e.source, e.target):
                if endpoint not in id_set:
                    raise ValueError(f"edge references unknown node: {endpoint!r}")
            src = by_id[e.source]
            if e.source_port and src.outputs and e.source_port not in {p.name for p in src.outputs}:
                raise ValueError(f"edge source port {e.source_port!r} not on node {e.source!r}")
            tgt = by_id[e.target]
            if e.target_port and tgt.inputs and e.target_port not in {p.name for p in tgt.inputs}:
                raise ValueError(f"edge target port {e.target_port!r} not on node {e.target!r}")
        return self

    def node(self, node_id: str) -> Node:
        for n in self.nodes:
            if n.id == node_id:
                return n
        raise KeyError(node_id)

    def successors(self, node_id: str) -> tuple[str, ...]:
        return tuple(e.target for e in self.edges if e.source == node_id)

    def predecessors(self, node_id: str) -> tuple[str, ...]:
        return tuple(e.source for e in self.edges if e.target == node_id)

    def nodes_with(self, capability: Capability) -> tuple[Node, ...]:
        return tuple(n for n in self.nodes if capability in n.capabilities)

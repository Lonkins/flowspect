# Graph IR

Every importer targets one intermediate representation. Rules and the taint engine
operate purely on the IR and never see builder-specific formats.

## Graph

A `Graph` is a flow: a name, a source format, and immutable tuples of nodes and
edges. Invariants are enforced on construction — unique node ids, edge endpoints
that exist, and declared ports that are real.

```python
from flowspect.importers import import_file

graph = import_file(Path("flow.json"))
graph.nodes            # tuple[Node, ...]
graph.edges            # tuple[Edge, ...]
graph.successors("n")  # ids reachable in one forward hop
graph.nodes_with(Capability.CODE_EXECUTION)
```

## Node

```python
Node(
    id="Agent-1",
    type="Agent",                       # builder-native component type
    label="Support Agent",              # display name
    capabilities=frozenset({Capability.LLM}),
    inputs=(...), outputs=(...),        # declared ports (optional)
    config={"system_prompt": "..."},    # normalized scalar settings
)
```

Nodes are frozen (immutable). `node.has(cap)` and `node.display` are the common
accessors.

## Capabilities

Capabilities are the semantic vocabulary rules match on. Importers assign them;
rules and the engine read them.

| Group | Capabilities |
|-------|--------------|
| Origins | `untrusted_input`, `trusted_input`, `web_fetch`, `sensitive_data`, `secrets` |
| Processing | `llm`, `memory`, `subflow` |
| Dangerous effects (sinks) | `code_execution`, `sql_execution`, `outbound_http`, `messaging`, `file_read`, `file_write`, `state_change`, `deserialization` |
| Mitigations | `input_validation`, `output_validation`, `authentication` |

!!! tip
    Capability **values** (the strings above) are the stable API that rule YAML
    references. Renaming one is a breaking change.

## Edge

```python
Edge(source="A", target="B", source_port="out", target_port="in", kind=EdgeKind.DATA)
```

`kind` is `data` (ordinary forward flow) or `tool` (a tool binding drawn
`tool → agent`, traversed both ways by the engine). Ports are optional; when a node
declares none, any port name on its edges is accepted.

## Working with the IR directly

```python
from flowspect.ir import Capability, Edge, Graph, Node
from flowspect.analysis import analyze
from flowspect.rules import load_builtin_rules

graph = Graph(
    name="demo",
    source_format="ir",
    nodes=(
        Node(id="in", type="Chat", capabilities=frozenset({Capability.UNTRUSTED_INPUT})),
        Node(id="sh", type="Shell", capabilities=frozenset({Capability.CODE_EXECUTION})),
    ),
    edges=(Edge(source="in", target="sh"),),
)
for finding in analyze(graph, load_builtin_rules()):
    print(finding.rule_id, finding.path_labels)
```

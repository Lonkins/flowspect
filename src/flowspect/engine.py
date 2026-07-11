"""Taint reachability engine over the Graph IR.

Given a graph and three node-id sets — sources, sinks, sanitizers — the engine
finds directed data-flow paths from a source to a sink that are *not* neutralised
by a sanitizer along the way. It is capability-agnostic: rules resolve their
capability predicates to node-id sets and call :func:`find_taint_paths`.

Traversal rules
---------------
* **Data edges** propagate taint forward (source → target).
* **Tool edges** propagate *both* ways. Every builder draws an agent's tool as
  ``tool → agent``; the tool result flows forward into the agent, and the agent
  (now possibly tainted) controls the tool's arguments, so taint also flows
  ``agent → tool``. Without the reverse direction, prompt-injection→execution
  paths are invisible.
* **Sanitizers** stop propagation: taint that reaches a sanitizer node is
  neutralised and does not flow to that node's successors, and the sanitizer node
  is not itself reported as a tainted sink. This is the standard taint model —
  a validated/guarded boundary cleans the data crossing it.
* **Unknown nodes** (no capability tags) are taint-transparent pass-throughs.
  Sub-flow nodes are opaque and treated the same conservative way: taint in →
  taint out.
* **Loops** terminate via a visited set (breadth-first, shortest path wins).

The engine reports one canonical (shortest) path per (source, sink) pair —
enumerating every path is exponential and adds no signal for a reviewer.
"""

from collections import deque
from collections.abc import Iterable, Mapping

from pydantic import BaseModel, ConfigDict

from flowspect.ir import EdgeKind, Graph


class TaintPath(BaseModel):
    """A concrete tainted data-flow: the node ids from source to sink, inclusive."""

    model_config = ConfigDict(frozen=True)

    source: str
    sink: str
    nodes: tuple[str, ...]

    @property
    def length(self) -> int:
        """Number of edges traversed."""
        return len(self.nodes) - 1


def _adjacency(graph: Graph) -> Mapping[str, list[str]]:
    """Directed taint-flow adjacency: data edges forward, tool edges both ways."""
    adj: dict[str, list[str]] = {n.id: [] for n in graph.nodes}
    for edge in graph.edges:
        adj[edge.source].append(edge.target)
        if edge.kind is EdgeKind.TOOL:
            adj[edge.target].append(edge.source)
    return adj


def find_taint_paths(
    graph: Graph,
    *,
    sources: Iterable[str],
    sinks: Iterable[str],
    sanitizers: Iterable[str] = (),
) -> list[TaintPath]:
    """Find unsanitised taint paths from any source to any sink.

    A source that is itself a sink is not reported — taint must *flow* to a
    distinct sink for there to be a data-flow finding. Results are sorted by
    (source, sink) for deterministic output.
    """
    sink_set = set(sinks)
    sanitizer_set = set(sanitizers)
    adj = _adjacency(graph)
    node_ids = {n.id for n in graph.nodes}

    paths: list[TaintPath] = []
    for source in sorted(set(sources)):
        if source not in node_ids:
            continue
        # BFS from this source; parent pointers reconstruct the shortest path.
        parent: dict[str, str | None] = {source: None}
        queue: deque[str] = deque([source])
        while queue:
            current = queue.popleft()
            # A sanitizer neutralises taint: reachable, but taint stops here.
            # (The source itself always emits taint, even if it is a sanitizer.)
            if current in sanitizer_set and current != source:
                continue
            if current in sink_set and current != source:
                paths.append(
                    TaintPath(
                        source=source,
                        sink=current,
                        nodes=tuple(_reconstruct(parent, current)),
                    )
                )
                # keep traversing: a sink may sit mid-flow before another sink
            for nxt in adj.get(current, ()):
                if nxt not in parent:
                    parent[nxt] = current
                    queue.append(nxt)
    paths.sort(key=lambda p: (p.source, p.sink, p.nodes))
    return paths


def reachable_from(
    graph: Graph, sources: Iterable[str], *, sanitizers: Iterable[str] = ()
) -> set[str]:
    """Set of nodes reachable from any source (taint semantics, sanitizers block)."""
    sanitizer_set = set(sanitizers)
    adj = _adjacency(graph)
    node_ids = {n.id for n in graph.nodes}
    seen: set[str] = set()
    queue: deque[str] = deque(s for s in set(sources) if s in node_ids)
    seen.update(queue)
    while queue:
        current = queue.popleft()
        if current in sanitizer_set:
            continue
        for nxt in adj.get(current, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _reconstruct(parent: Mapping[str, str | None], target: str) -> list[str]:
    chain: list[str] = []
    node: str | None = target
    while node is not None:
        chain.append(node)
        node = parent[node]
    chain.reverse()
    return chain

"""Apply compiled rules to a Graph IR and produce findings.

The analyzer resolves each rule's matchers to node-id sets, then:
* **taint** rules call the reachability engine (source→sink, minus sanitizers),
  optionally gated by ``also_reachable_from`` (a second class must reach the sink)
  and ``path_contains`` (a node on the path must match);
* **structural** rules test each matched node against ``require``/``forbid``.

Findings carry the concrete node path and human-readable labels so reporters can
render the exact flow.
"""

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from flowspect.engine import find_taint_paths, reachable_from
from flowspect.ir import Graph, Node
from flowspect.rules.schema import NodeMatcher, Rule, Severity


class Finding(BaseModel):
    """A single rule violation located in one graph."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    title: str
    message: str
    remediation: str
    references: tuple[str, ...]
    graph_name: str
    source_format: str
    source_path: str | None
    path: tuple[str, ...]  # node ids, source→sink (single node for structural)
    path_labels: tuple[str, ...]  # display names, aligned with path

    @property
    def primary_node(self) -> str:
        """The node the finding is anchored to (the sink / the offending node)."""
        return self.path[-1]


def _matching_ids(matcher: NodeMatcher | None, nodes: Iterable[Node]) -> set[str]:
    if matcher is None:
        return set()
    return {n.id for n in nodes if matcher.matches(n)}


def _labels(graph: Graph, ids: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(graph.node(i).display for i in ids)


def _analyze_taint(rule: Rule, graph: Graph) -> list[Finding]:
    if rule.source is None or rule.sink is None:  # schema guarantees this; narrows for mypy
        return []
    sources = _matching_ids(rule.source, graph.nodes)
    sinks = _matching_ids(rule.sink, graph.nodes)
    if not sources or not sinks:
        return []
    sanitizers = _matching_ids(rule.sanitizer, graph.nodes)
    paths = find_taint_paths(graph, sources=sources, sinks=sinks, sanitizers=sanitizers)

    # Gate: the sink must also be taint-reachable from a second class.
    if rule.also_reachable_from is not None:
        second = _matching_ids(rule.also_reachable_from, graph.nodes)
        reachable_sinks = reachable_from(graph, second, sanitizers=sanitizers) if second else set()
        paths = [p for p in paths if p.sink in reachable_sinks]

    # Gate: the tainted path must pass through a matching node.
    if rule.path_contains is not None:
        gate = _matching_ids(rule.path_contains, graph.nodes)
        paths = [p for p in paths if gate.intersection(p.nodes)]

    return [_make_finding(rule, graph, path=p.nodes) for p in paths]


def _analyze_structural(rule: Rule, graph: Graph) -> list[Finding]:
    if rule.match is None:  # schema guarantees this; guard for the type checker
        return []
    findings: list[Finding] = []
    for node in graph.nodes:
        if not rule.match.matches(node):
            continue
        violated = (rule.require is not None and not rule.require.matches(node)) or (
            rule.forbid is not None and rule.forbid.matches(node)
        )
        if violated:
            findings.append(_make_finding(rule, graph, path=(node.id,)))
    return findings


def _make_finding(rule: Rule, graph: Graph, *, path: tuple[str, ...]) -> Finding:
    labels = _labels(graph, path)
    if len(path) > 1:
        flow = " → ".join(labels)
        message = f"{rule.title}: {flow}"
    else:
        message = f"{rule.title}: {labels[0]}"
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        title=rule.title,
        message=message,
        remediation=rule.remediation,
        references=rule.references,
        graph_name=graph.name,
        source_format=graph.source_format,
        source_path=graph.source_path,
        path=path,
        path_labels=labels,
    )


def analyze(graph: Graph, rules: Iterable[Rule]) -> list[Finding]:
    """Run all rules over one graph. Findings are sorted most-severe first."""
    findings: list[Finding] = []
    for rule in rules:
        if rule.kind == "taint":
            findings.extend(_analyze_taint(rule, graph))
        else:
            findings.extend(_analyze_structural(rule, graph))
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.path))
    return findings

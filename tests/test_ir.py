import pytest
from pydantic import ValidationError

from flowspect.ir import Capability, Edge, Graph, Node, Port


def node(node_id: str) -> Node:
    return Node(id=node_id, type="Test")


def test_graph_holds_nodes_and_edges() -> None:
    g = Graph(
        name="f",
        source_format="ir",
        nodes=(node("a"), node("b")),
        edges=(Edge(source="a", target="b"),),
    )
    assert g.node("a").id == "a"
    assert g.successors("a") == ("b",)
    assert g.predecessors("b") == ("a",)
    assert g.successors("b") == ()


def test_duplicate_node_ids_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate node ids"):
        Graph(name="f", source_format="ir", nodes=(node("a"), node("a")))


def test_edge_to_unknown_node_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown node"):
        Graph(
            name="f",
            source_format="ir",
            nodes=(node("a"),),
            edges=(Edge(source="a", target="ghost"),),
        )


def test_edge_port_must_exist_when_ports_declared() -> None:
    a = Node(id="a", type="T", outputs=(Port(name="out"),))
    b = Node(id="b", type="T", inputs=(Port(name="in"),))
    Graph(
        name="ok",
        source_format="ir",
        nodes=(a, b),
        edges=(Edge(source="a", target="b", source_port="out", target_port="in"),),
    )
    with pytest.raises(ValidationError, match="source port"):
        Graph(
            name="bad",
            source_format="ir",
            nodes=(a, b),
            edges=(Edge(source="a", target="b", source_port="nope"),),
        )
    with pytest.raises(ValidationError, match="target port"):
        Graph(
            name="bad",
            source_format="ir",
            nodes=(a, b),
            edges=(Edge(source="a", target="b", target_port="nope"),),
        )


def test_edge_ports_lenient_when_node_declares_none() -> None:
    # importers may not know port schemas; undeclared ports accept any name
    Graph(
        name="f",
        source_format="ir",
        nodes=(node("a"), node("b")),
        edges=(Edge(source="a", target="b", source_port="anything"),),
    )


def test_capabilities_and_lookup() -> None:
    hook = Node(id="w", type="Webhook", capabilities=frozenset({Capability.UNTRUSTED_INPUT}))
    shell = Node(id="s", type="Shell", capabilities=frozenset({Capability.CODE_EXECUTION}))
    g = Graph(name="f", source_format="ir", nodes=(hook, shell))
    assert hook.has(Capability.UNTRUSTED_INPUT)
    assert not hook.has(Capability.CODE_EXECUTION)
    assert g.nodes_with(Capability.CODE_EXECUTION) == (shell,)


def test_nodes_are_immutable() -> None:
    n = node("a")
    with pytest.raises(ValidationError):
        n.id = "b"  # type: ignore[misc]


def test_display_prefers_label() -> None:
    assert Node(id="a", type="Webhook").display == "Webhook"
    assert Node(id="a", type="Webhook", label="Public intake").display == "Public intake"


def test_unknown_node_lookup_raises() -> None:
    g = Graph(name="f", source_format="ir", nodes=(node("a"),))
    with pytest.raises(KeyError):
        g.node("missing")


def test_capability_values_are_stable_strings() -> None:
    # rule YAML references these by value; renames are breaking changes
    assert Capability("untrusted_input") is Capability.UNTRUSTED_INPUT
    assert Capability.CODE_EXECUTION.value == "code_execution"

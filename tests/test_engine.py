"""Taint engine tests — built on hand-constructed IR graphs so each traversal
rule (forward flow, sanitizer blocking, fan-in/out, tool reverse, loops,
sub-flow pass-through) is isolated."""

from flowspect.engine import find_taint_paths, reachable_from
from flowspect.ir import Capability, Edge, EdgeKind, Graph, Node


def _n(node_id: str, *caps: Capability) -> Node:
    return Node(id=node_id, type=node_id, capabilities=frozenset(caps))


def _g(nodes: list[Node], edges: list[Edge]) -> Graph:
    return Graph(name="t", source_format="ir", nodes=tuple(nodes), edges=tuple(edges))


def test_simple_forward_path() -> None:
    g = _g(
        [_n("src"), _n("mid"), _n("sink")],
        [Edge(source="src", target="mid"), Edge(source="mid", target="sink")],
    )
    paths = find_taint_paths(g, sources=["src"], sinks=["sink"])
    assert len(paths) == 1
    assert paths[0].nodes == ("src", "mid", "sink")
    assert paths[0].length == 2


def test_no_path_when_disconnected() -> None:
    g = _g([_n("src"), _n("sink")], [])
    assert find_taint_paths(g, sources=["src"], sinks=["sink"]) == []


def test_sanitizer_blocks_flow() -> None:
    g = _g(
        [_n("src"), _n("clean"), _n("sink")],
        [Edge(source="src", target="clean"), Edge(source="clean", target="sink")],
    )
    assert find_taint_paths(g, sources=["src"], sinks=["sink"]) != []
    assert find_taint_paths(g, sources=["src"], sinks=["sink"], sanitizers=["clean"]) == []


def test_sanitizer_only_blocks_the_path_through_it() -> None:
    # src fans to two sinks; sanitizer on one branch only
    g = _g(
        [_n("src"), _n("clean"), _n("safe_sink"), _n("bad_sink")],
        [
            Edge(source="src", target="clean"),
            Edge(source="clean", target="safe_sink"),
            Edge(source="src", target="bad_sink"),
        ],
    )
    paths = find_taint_paths(
        g, sources=["src"], sinks=["safe_sink", "bad_sink"], sanitizers=["clean"]
    )
    assert [p.sink for p in paths] == ["bad_sink"]


def test_fan_in_multiple_sources() -> None:
    g = _g(
        [_n("s1"), _n("s2"), _n("join"), _n("sink")],
        [
            Edge(source="s1", target="join"),
            Edge(source="s2", target="join"),
            Edge(source="join", target="sink"),
        ],
    )
    paths = find_taint_paths(g, sources=["s1", "s2"], sinks=["sink"])
    assert {p.source for p in paths} == {"s1", "s2"}
    assert all(p.sink == "sink" for p in paths)


def test_tool_edge_reverses_for_injection_to_exec() -> None:
    # untrusted -> agent (data);  exec_tool -> agent (tool binding)
    # taint must reach exec_tool via the reversed tool edge
    g = _g(
        [_n("untrusted"), _n("agent"), _n("exec_tool")],
        [
            Edge(source="untrusted", target="agent"),
            Edge(source="exec_tool", target="agent", kind=EdgeKind.TOOL),
        ],
    )
    paths = find_taint_paths(g, sources=["untrusted"], sinks=["exec_tool"])
    assert len(paths) == 1
    assert paths[0].nodes == ("untrusted", "agent", "exec_tool")


def test_data_edge_does_not_reverse() -> None:
    g = _g(
        [_n("a"), _n("b")],
        [Edge(source="a", target="b", kind=EdgeKind.DATA)],
    )
    # b is not a source, so nothing flows a<-b
    assert find_taint_paths(g, sources=["b"], sinks=["a"]) == []


def test_loops_terminate() -> None:
    g = _g(
        [_n("src"), _n("a"), _n("b"), _n("sink")],
        [
            Edge(source="src", target="a"),
            Edge(source="a", target="b"),
            Edge(source="b", target="a"),  # cycle
            Edge(source="b", target="sink"),
        ],
    )
    paths = find_taint_paths(g, sources=["src"], sinks=["sink"])
    assert len(paths) == 1
    assert paths[0].nodes[0] == "src" and paths[0].nodes[-1] == "sink"


def test_subflow_is_taint_transparent() -> None:
    # subflow node has no special handling: taint passes through
    g = _g(
        [_n("src"), _n("subflow", Capability.SUBFLOW), _n("sink")],
        [Edge(source="src", target="subflow"), Edge(source="subflow", target="sink")],
    )
    assert find_taint_paths(g, sources=["src"], sinks=["sink"]) != []


def test_source_equal_sink_not_reported() -> None:
    g = _g([_n("both")], [])
    assert find_taint_paths(g, sources=["both"], sinks=["both"]) == []


def test_multiple_sinks_on_one_path() -> None:
    g = _g(
        [_n("src"), _n("sink1"), _n("sink2")],
        [Edge(source="src", target="sink1"), Edge(source="sink1", target="sink2")],
    )
    paths = find_taint_paths(g, sources=["src"], sinks=["sink1", "sink2"])
    assert {p.sink for p in paths} == {"sink1", "sink2"}


def test_unknown_source_or_sink_ids_ignored() -> None:
    g = _g([_n("src"), _n("sink")], [Edge(source="src", target="sink")])
    assert find_taint_paths(g, sources=["ghost"], sinks=["sink"]) == []
    assert find_taint_paths(g, sources=["src"], sinks=["ghost"]) == []


def test_deterministic_ordering() -> None:
    g = _g(
        [_n("b"), _n("a"), _n("z")],
        [Edge(source="a", target="z"), Edge(source="b", target="z")],
    )
    paths = find_taint_paths(g, sources=["a", "b"], sinks=["z"])
    assert [p.source for p in paths] == ["a", "b"]


def test_reachable_from() -> None:
    g = _g(
        [_n("src"), _n("a"), _n("b"), _n("island")],
        [Edge(source="src", target="a"), Edge(source="a", target="b")],
    )
    assert reachable_from(g, ["src"]) == {"src", "a", "b"}
    assert reachable_from(g, ["src"], sanitizers=["a"]) == {"src", "a"}

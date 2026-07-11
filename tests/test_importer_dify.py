from pathlib import Path

import pytest

from flowspect.importers import FlowParseError, import_file
from flowspect.importers.dify import DifyImporter
from flowspect.ir import Capability, Graph

FIXTURES = Path(__file__).parent / "fixtures"
RESEARCH = FIXTURES / "dify" / "research-workflow.yml"


@pytest.fixture(scope="module")
def graph() -> Graph:
    return import_file(RESEARCH)


def test_detects_and_loads(graph: Graph) -> None:
    assert graph.source_format == "dify"
    assert graph.name == "Research Assistant"


def test_untyped_note_node_skipped(graph: Graph) -> None:
    ids = {n.id for n in graph.nodes}
    assert "note-1" not in ids
    assert len(graph.nodes) == 7


def test_node_type_capabilities(graph: Graph) -> None:
    caps = {n.id: n.capabilities for n in graph.nodes}
    assert Capability.UNTRUSTED_INPUT in caps["start-1"]
    assert Capability.LLM in caps["llm-1"]
    assert Capability.SENSITIVE_DATA in caps["kb-1"]
    assert Capability.CODE_EXECUTION in caps["code-1"]
    assert caps["answer-1"] == frozenset()


def test_tool_provider_capabilities(graph: Graph) -> None:
    caps = {n.id: n.capabilities for n in graph.nodes}
    assert Capability.WEB_FETCH in caps["search-1"]  # tavily
    assert Capability.MESSAGING in caps["slack-1"]
    assert Capability.STATE_CHANGE in caps["slack-1"]


def test_edges_and_branch_handles(graph: Graph) -> None:
    assert len(graph.edges) == 7
    # default react-flow handle "source" collapses to None
    assert all(e.source_port is None for e in graph.edges)
    assert graph.successors("llm-1") == ("code-1", "slack-1", "answer-1")


def test_non_graph_mode_rejected() -> None:
    imp = DifyImporter()
    with pytest.raises(FlowParseError, match="no workflow graph"):
        imp.load({"app": {"name": "old", "mode": "chat"}, "kind": "app"})


def test_detect() -> None:
    imp = DifyImporter()
    assert imp.detect({"app": {"mode": "workflow"}, "kind": "app", "workflow": {}})
    assert not imp.detect({"data": {"nodes": [], "edges": []}})  # langflow
    assert not imp.detect({"nodes": [], "connections": {}})  # n8n
    assert not imp.detect([1, 2])


def test_branch_handle_preserved() -> None:
    imp = DifyImporter()
    g = imp.load(
        {
            "app": {"name": "cond", "mode": "workflow"},
            "kind": "app",
            "workflow": {
                "graph": {
                    "nodes": [
                        {"id": "a", "data": {"type": "if-else", "title": "Branch"}},
                        {"id": "b", "data": {"type": "answer", "title": "Yes"}},
                    ],
                    "edges": [
                        {"source": "a", "target": "b", "sourceHandle": "true"},
                    ],
                }
            },
        }
    )
    assert g.edges[0].source_port == "true"

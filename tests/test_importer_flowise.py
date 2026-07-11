from pathlib import Path

import pytest

from flowspect.importers import import_file
from flowspect.importers.flowise import FlowiseImporter
from flowspect.ir import Capability, EdgeKind, Graph

FIXTURES = Path(__file__).parent / "fixtures"
AGENT = FIXTURES / "flowise" / "agent-with-tools.json"


@pytest.fixture(scope="module")
def graph() -> Graph:
    return import_file(AGENT)


def test_detects_flowise_not_langflow(graph: Graph) -> None:
    assert graph.source_format == "flowise"
    assert len(graph.nodes) == 4


def test_name_and_category_capabilities(graph: Graph) -> None:
    caps = {n.id: n.capabilities for n in graph.nodes}
    assert Capability.LLM in caps["chatOpenAI_0"]  # category "Chat Models"
    assert Capability.WEB_FETCH in caps["serpAPI_0"]  # name serpapi
    assert Capability.CODE_EXECUTION in caps["customFunction_0"]
    assert Capability.LLM in caps["toolAgent_0"]  # category "Agents" -> follows instructions


def test_inline_credential_tagged_secret(graph: Graph) -> None:
    assert Capability.SECRETS in graph.node("chatOpenAI_0").capabilities


def test_tool_anchor_edges_marked_tool(graph: Graph) -> None:
    tool_edges = [e for e in graph.edges if e.target == "toolAgent_0" and e.kind is EdgeKind.TOOL]
    assert {e.source for e in tool_edges} == {"serpAPI_0", "customFunction_0"}
    model_edge = next(e for e in graph.edges if e.source == "chatOpenAI_0")
    assert model_edge.kind is EdgeKind.DATA


def test_detect_rejects_langflow_shape() -> None:
    imp = FlowiseImporter()
    # langflow: node.data has no category/inputAnchors
    assert not imp.detect({"nodes": [{"data": {"type": "ChatInput"}}], "edges": []})
    assert imp.detect({"nodes": [{"data": {"name": "x", "category": "Tools"}}], "edges": []})

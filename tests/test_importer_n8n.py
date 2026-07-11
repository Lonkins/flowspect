from pathlib import Path

import pytest

from flowspect.importers import FlowParseError, import_file
from flowspect.importers.n8n import N8nImporter
from flowspect.ir import Capability, EdgeKind, Graph

FIXTURES = Path(__file__).parent / "fixtures"
WEBHOOK = FIXTURES / "n8n" / "webhook-to-shell.json"


@pytest.fixture(scope="module")
def graph() -> Graph:
    return import_file(WEBHOOK)


def test_detects_and_keys_by_name(graph: Graph) -> None:
    assert graph.source_format == "n8n"
    assert {n.id for n in graph.nodes} == {"Webhook", "Run Deploy", "Notify Slack"}


def test_connections_become_edges_via_names(graph: Graph) -> None:
    assert graph.successors("Webhook") == ("Run Deploy",)
    assert graph.successors("Run Deploy") == ("Notify Slack",)


def test_kind_capabilities(graph: Graph) -> None:
    caps = {n.id: n.capabilities for n in graph.nodes}
    assert Capability.UNTRUSTED_INPUT in caps["Webhook"]
    assert Capability.CODE_EXECUTION in caps["Run Deploy"]
    # POST httpRequest is an outbound sink, not a fetch
    assert Capability.OUTBOUND_HTTP in caps["Notify Slack"]
    assert Capability.WEB_FETCH not in caps["Notify Slack"]


def test_get_httprequest_is_web_fetch() -> None:
    g = N8nImporter().load(
        {
            "name": "fetcher",
            "nodes": [
                {
                    "name": "Fetch",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {"url": "https://x", "method": "GET"},
                }
            ],
            "connections": {},
        }
    )
    caps = g.node("Fetch").capabilities
    assert Capability.WEB_FETCH in caps
    assert Capability.OUTBOUND_HTTP not in caps


def test_ai_tool_connections_are_tool_edges() -> None:
    g = N8nImporter().load(
        {
            "name": "ai",
            "nodes": [
                {"name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
                {"name": "Calc", "type": "@n8n/n8n-nodes-langchain.toolCode", "parameters": {}},
            ],
            "connections": {
                "Calc": {"ai_tool": [[{"node": "Agent", "type": "ai_tool", "index": 0}]]}
            },
        }
    )
    assert g.edges[0].kind is EdgeKind.TOOL
    assert Capability.LLM in g.node("Agent").capabilities


def test_duplicate_node_name_rejected() -> None:
    with pytest.raises(FlowParseError, match="duplicate n8n node name"):
        N8nImporter().load(
            {
                "nodes": [
                    {"name": "X", "type": "n8n-nodes-base.noOp", "parameters": {}},
                    {"name": "X", "type": "n8n-nodes-base.noOp", "parameters": {}},
                ],
                "connections": {},
            }
        )


def test_detect() -> None:
    imp = N8nImporter()
    assert imp.detect({"nodes": [], "connections": {}})
    assert not imp.detect({"nodes": [], "edges": []})  # flowise/langflow
    assert not imp.detect({"app": {}})

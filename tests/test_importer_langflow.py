from pathlib import Path

import pytest

from flowspect.importers import UnsupportedFormatError, import_file, import_path
from flowspect.importers.langflow import LangflowImporter
from flowspect.ir import Capability, Graph

FIXTURES = Path(__file__).parent / "fixtures"
SUPPORT_AGENT = FIXTURES / "langflow" / "support-agent.json"


@pytest.fixture(scope="module")
def graph() -> Graph:
    return import_file(SUPPORT_AGENT)


def test_detects_and_loads_langflow_export(graph: Graph) -> None:
    assert graph.source_format == "langflow"
    assert graph.name == "Support Agent"
    assert graph.source_path == str(SUPPORT_AGENT)


def test_note_nodes_and_their_edges_are_skipped(graph: Graph) -> None:
    ids = {n.id for n in graph.nodes}
    assert "undefined-a1b2c" not in ids
    assert len(graph.nodes) == 7
    assert all(e.source != "undefined-a1b2c" for e in graph.edges)
    assert len(graph.edges) == 6


def test_capability_mapping(graph: Graph) -> None:
    caps = {n.id: n.capabilities for n in graph.nodes}
    assert Capability.UNTRUSTED_INPUT in caps["ChatInput-b6UCc"]
    assert Capability.LLM in caps["Agent-Ff3Lp"]
    assert Capability.CODE_EXECUTION in caps["PythonREPLTool-Vc8Wd"]
    assert Capability.OUTBOUND_HTTP in caps["APIRequest-Tr4Hs"]
    assert Capability.SENSITIVE_DATA in caps["AstraDB-K2mNv"]
    assert caps["Prompt-9xQz1"] == frozenset()  # pass-through


def test_hardcoded_secret_tagged_and_redacted(graph: Graph) -> None:
    agent = graph.node("Agent-Ff3Lp")
    assert Capability.SECRETS in agent.capabilities
    assert agent.config["api_key"] == "***"
    # empty SecretStr value on AstraDB is NOT a hardcoded secret
    astra = graph.node("AstraDB-K2mNv")
    assert Capability.SECRETS not in astra.capabilities


def test_edge_ports_from_handles(graph: Graph) -> None:
    e = next(e for e in graph.edges if e.target == "Prompt-9xQz1" and e.source.startswith("Chat"))
    assert e.source_port == "message"
    assert e.target_port == "question"


def test_config_flattened_to_plain_values(graph: Graph) -> None:
    api = graph.node("APIRequest-Tr4Hs")
    assert api.config["urls"] == "https://crm.example.com/api/tickets"
    assert api.config["method"] == "POST"
    assert api.label == "CRM Update"


def test_detect_rejects_other_formats() -> None:
    imp = LangflowImporter()
    assert not imp.detect({"nodes": [], "connections": {}})  # n8n-ish
    assert not imp.detect({"app": {"mode": "workflow"}})  # dify-ish
    assert not imp.detect([1, 2])
    assert not imp.detect({"data": "not-a-dict"})


def test_unsupported_file_raises(tmp_path: Path) -> None:
    f = tmp_path / "random.json"
    f.write_text('{"hello": "world"}')
    with pytest.raises(UnsupportedFormatError):
        import_file(f)


def test_import_path_directory_skips_unrecognised(tmp_path: Path) -> None:
    (tmp_path / "noise.json").write_text('{"not": "a flow"}')
    (tmp_path / "broken.yaml").write_text("::: not yaml :::")
    (tmp_path / "flow.json").write_text(SUPPORT_AGENT.read_text())
    graphs = import_path(tmp_path)
    assert [g.name for g in graphs] == ["Support Agent"]


def test_import_path_missing_raises(tmp_path: Path) -> None:
    from flowspect.importers import FlowParseError

    with pytest.raises(FlowParseError, match="does not exist"):
        import_path(tmp_path / "nope")


def test_real_export_shape_minimal() -> None:
    # tiniest structurally-valid export: no nodes, no edges
    g = LangflowImporter().load({"name": "empty", "data": {"nodes": [], "edges": []}})
    assert g.nodes == ()

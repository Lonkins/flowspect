from pathlib import Path

from flowspect.analysis import analyze
from flowspect.importers import import_file
from flowspect.ir import Capability, Edge, Graph, Node
from flowspect.rules import load_builtin_rules, load_rules_text
from flowspect.rules.schema import Rule, Severity

FIXTURES = Path(__file__).parent / "fixtures"
SUPPORT_AGENT = FIXTURES / "langflow" / "support-agent.json"


def _rule_taint(**kw: object) -> Rule:
    base: dict[str, object] = {
        "id": "T-1",
        "kind": "taint",
        "severity": Severity.HIGH,
        "title": "taint",
    }
    base.update(kw)
    return Rule.model_validate(base)


def test_taint_rule_produces_path_finding() -> None:
    g = import_file(SUPPORT_AGENT)
    rule = _rule_taint(
        source={"capability": "untrusted_input"},
        sink={"capability": "code_execution"},
    )
    findings = analyze(g, [rule])
    assert len(findings) == 1
    f = findings[0]
    assert f.path == ("ChatInput-b6UCc", "Prompt-9xQz1", "Agent-Ff3Lp", "PythonREPLTool-Vc8Wd")
    assert "→" in f.message
    assert f.primary_node == "PythonREPLTool-Vc8Wd"


def test_sanitizer_suppresses_finding() -> None:
    g = Graph(
        name="g",
        source_format="ir",
        nodes=(
            Node(id="in", type="in", capabilities=frozenset({Capability.UNTRUSTED_INPUT})),
            Node(id="guard", type="guard", capabilities=frozenset({Capability.OUTPUT_VALIDATION})),
            Node(id="exec", type="exec", capabilities=frozenset({Capability.CODE_EXECUTION})),
        ),
        edges=(Edge(source="in", target="guard"), Edge(source="guard", target="exec")),
    )
    rule = _rule_taint(
        source={"capability": "untrusted_input"},
        sink={"capability": "code_execution"},
        sanitizer={"capability": "output_validation"},
    )
    assert analyze(g, [rule]) == []


def test_also_reachable_from_gate() -> None:
    g = import_file(SUPPORT_AGENT)
    # trifecta: untrusted -> outbound_http AND sensitive_data reaches that sink
    rule = _rule_taint(
        id="T-TRI",
        severity=Severity.CRITICAL,
        source={"capability": "untrusted_input"},
        sink={"any_capabilities": ["outbound_http", "messaging"]},
        also_reachable_from={"capability": "sensitive_data"},
    )
    findings = analyze(g, [rule])
    assert len(findings) == 1
    assert findings[0].primary_node == "APIRequest-Tr4Hs"


def test_also_reachable_from_gate_filters_when_absent() -> None:
    # untrusted -> http, but no sensitive data reaches the http sink
    g = Graph(
        name="g",
        source_format="ir",
        nodes=(
            Node(id="in", type="in", capabilities=frozenset({Capability.UNTRUSTED_INPUT})),
            Node(id="http", type="http", capabilities=frozenset({Capability.OUTBOUND_HTTP})),
            Node(id="kb", type="kb", capabilities=frozenset({Capability.SENSITIVE_DATA})),
        ),
        edges=(Edge(source="in", target="http"),),  # kb is disconnected
    )
    rule = _rule_taint(
        source={"capability": "untrusted_input"},
        sink={"capability": "outbound_http"},
        also_reachable_from={"capability": "sensitive_data"},
    )
    assert analyze(g, [rule]) == []


def test_path_contains_gate() -> None:
    g = import_file(SUPPORT_AGENT)
    rule = _rule_taint(
        source={"capability": "untrusted_input"},
        sink={"capability": "outbound_http"},
        path_contains={"capability": "llm"},
    )
    assert len(analyze(g, [rule])) == 1
    rule_absent = _rule_taint(
        source={"capability": "untrusted_input"},
        sink={"capability": "outbound_http"},
        path_contains={"capability": "deserialization"},
    )
    assert analyze(g, [rule_absent]) == []


def test_structural_require_and_forbid() -> None:
    g = Graph(
        name="g",
        source_format="ir",
        nodes=(
            Node(id="hook", type="Webhook", capabilities=frozenset({Capability.UNTRUSTED_INPUT})),
        ),
    )
    require_rule = Rule.model_validate(
        {
            "id": "S-AUTH",
            "kind": "structural",
            "severity": "high",
            "title": "webhook must authenticate",
            "match": {"capability": "untrusted_input"},
            "require": {"capability": "authentication"},
        }
    )
    findings = analyze(g, [require_rule])
    assert len(findings) == 1
    assert findings[0].path == ("hook",)


def test_analyze_sorts_by_severity() -> None:
    g = import_file(SUPPORT_AGENT)
    low = _rule_taint(
        id="LOW-1",
        severity=Severity.LOW,
        source={"capability": "untrusted_input"},
        sink={"capability": "code_execution"},
    )
    crit = _rule_taint(
        id="CRIT-1",
        severity=Severity.CRITICAL,
        source={"capability": "untrusted_input"},
        sink={"capability": "code_execution"},
    )
    findings = analyze(g, [low, crit])
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]


def test_builtin_rules_fire_on_vulnerable_fixture() -> None:
    g = import_file(SUPPORT_AGENT)
    findings = analyze(g, load_builtin_rules())
    ids = {f.rule_id for f in findings}
    assert "FS-TRIFECTA-001" in ids
    assert "FS-INJECT-EXEC-001" in ids


def test_no_findings_when_no_sources() -> None:
    g = Graph(
        name="g",
        source_format="ir",
        nodes=(Node(id="x", type="x", capabilities=frozenset({Capability.LLM})),),
    )
    assert (
        analyze(
            g,
            load_rules_text(
                "id: Z-1\nkind: taint\nseverity: low\ntitle: t\n"
                "source: {capability: untrusted_input}\nsink: {capability: code_execution}\n"
            ),
        )
        == []
    )

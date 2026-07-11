"""Per-rule fixtures for the bundled pack.

Each rule gets a minimal IR graph it MUST flag (true positive) and one it MUST
NOT flag (false positive / safe variant, usually the same shape with a sanitizer
inserted or the offending edge removed). Building the graphs from terse specs
keeps 27 rule fixtures readable in one place and doubles as executable docs for
what each rule means.
"""

import pytest

from flowspect.analysis import analyze
from flowspect.ir import Capability as C
from flowspect.ir import Edge, EdgeKind, Graph, Node
from flowspect.rules import load_builtin_rules

RULES = load_builtin_rules()
_BY_ID = {r.id: r for r in RULES}

# node spec: (id, [capabilities]);  edge spec: (src, tgt) or (src, tgt, "tool")
NodeSpec = tuple[str, list[C]]
EdgeSpec = tuple[str, ...]


def _graph(nodes: list[NodeSpec], edges: list[EdgeSpec]) -> Graph:
    return Graph(
        name="fixture",
        source_format="ir",
        source_path="fixture.json",
        nodes=tuple(Node(id=nid, type=nid, capabilities=frozenset(caps)) for nid, caps in nodes),
        edges=tuple(
            Edge(
                source=e[0],
                target=e[1],
                kind=EdgeKind.TOOL if len(e) > 2 and e[2] == "tool" else EdgeKind.DATA,
            )
            for e in edges
        ),
    )


# For each rule: a graph that must flag it, and a graph that must not.
FIXTURES: dict[str, dict[str, Graph]] = {
    "FS-INJECT-EXEC-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.CODE_EXECUTION])], [("in", "x")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.CODE_EXECUTION])],
            [("in", "g"), ("g", "x")],
        ),
    },
    "FS-INJECT-SQL-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.SQL_EXECUTION])], [("in", "x")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.SQL_EXECUTION])],
            [("in", "g"), ("g", "x")],
        ),
    },
    "FS-INJECT-DESERIALIZE-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.DESERIALIZATION])], [("in", "x")]),
        "safe": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.DESERIALIZATION])], []),
    },
    "FS-INJECT-FILEWRITE-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.FILE_WRITE])], [("in", "x")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.FILE_WRITE])],
            [("in", "g"), ("g", "x")],
        ),
    },
    "FS-INJECT-STATECHANGE-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("x", [C.STATE_CHANGE])], [("in", "x")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.INPUT_VALIDATION]), ("x", [C.STATE_CHANGE])],
            [("in", "g"), ("g", "x")],
        ),
    },
    "FS-TRIFECTA-001": {
        "vuln": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("kb", [C.SENSITIVE_DATA]), ("out", [C.OUTBOUND_HTTP])],
            [("in", "out"), ("kb", "out")],
        ),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("kb", [C.SENSITIVE_DATA]), ("out", [C.OUTBOUND_HTTP])],
            [("in", "out")],  # sensitive data does not reach the sink
        ),
    },
    "FS-SECRET-HTTP-001": {
        "vuln": _graph([("s", [C.SECRETS]), ("out", [C.OUTBOUND_HTTP])], [("s", "out")]),
        "safe": _graph([("s", [C.SECRETS]), ("out", [C.OUTBOUND_HTTP])], []),
    },
    "FS-SECRET-MESSAGING-001": {
        "vuln": _graph([("s", [C.SECRETS]), ("m", [C.MESSAGING])], [("s", "m")]),
        "safe": _graph([("s", [C.SECRETS]), ("m", [C.MESSAGING])], []),
    },
    "FS-SENSITIVE-HTTP-001": {
        "vuln": _graph([("kb", [C.SENSITIVE_DATA]), ("out", [C.OUTBOUND_HTTP])], [("kb", "out")]),
        "safe": _graph(
            [("kb", [C.SENSITIVE_DATA]), ("g", [C.OUTPUT_VALIDATION]), ("out", [C.OUTBOUND_HTTP])],
            [("kb", "g"), ("g", "out")],
        ),
    },
    "FS-SENSITIVE-MESSAGING-001": {
        "vuln": _graph([("kb", [C.SENSITIVE_DATA]), ("m", [C.MESSAGING])], [("kb", "m")]),
        "safe": _graph(
            [("kb", [C.SENSITIVE_DATA]), ("g", [C.OUTPUT_VALIDATION]), ("m", [C.MESSAGING])],
            [("kb", "g"), ("g", "m")],
        ),
    },
    "FS-MEMORY-EXFIL-001": {
        "vuln": _graph([("mem", [C.MEMORY]), ("out", [C.OUTBOUND_HTTP])], [("mem", "out")]),
        "safe": _graph(
            [("mem", [C.MEMORY]), ("g", [C.OUTPUT_VALIDATION]), ("out", [C.OUTBOUND_HTTP])],
            [("mem", "g"), ("g", "out")],
        ),
    },
    "FS-SSRF-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("f", [C.WEB_FETCH])], [("in", "f")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.INPUT_VALIDATION]), ("f", [C.WEB_FETCH])],
            [("in", "g"), ("g", "f")],
        ),
    },
    "FS-INDIRECT-EXEC-001": {
        "vuln": _graph([("f", [C.WEB_FETCH]), ("x", [C.CODE_EXECUTION])], [("f", "x")]),
        "safe": _graph(
            [("f", [C.WEB_FETCH]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.CODE_EXECUTION])],
            [("f", "g"), ("g", "x")],
        ),
    },
    "FS-INDIRECT-SQL-001": {
        "vuln": _graph([("f", [C.WEB_FETCH]), ("x", [C.SQL_EXECUTION])], [("f", "x")]),
        "safe": _graph(
            [("f", [C.WEB_FETCH]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.SQL_EXECUTION])],
            [("f", "g"), ("g", "x")],
        ),
    },
    "FS-INDIRECT-TRIFECTA-001": {
        "vuln": _graph(
            [("f", [C.WEB_FETCH]), ("kb", [C.SENSITIVE_DATA]), ("out", [C.OUTBOUND_HTTP])],
            [("f", "out"), ("kb", "out")],
        ),
        "safe": _graph(
            [("f", [C.WEB_FETCH]), ("kb", [C.SENSITIVE_DATA]), ("out", [C.OUTBOUND_HTTP])],
            [("f", "out")],
        ),
    },
    "FS-TOOLRESULT-NOVALIDATE-001": {
        "vuln": _graph([("f", [C.WEB_FETCH]), ("m", [C.MESSAGING])], [("f", "m")]),
        "safe": _graph(
            [("f", [C.WEB_FETCH]), ("g", [C.OUTPUT_VALIDATION]), ("m", [C.MESSAGING])],
            [("f", "g"), ("g", "m")],
        ),
    },
    "FS-UNTRUSTED-MESSAGING-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("m", [C.MESSAGING])], [("in", "m")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.INPUT_VALIDATION]), ("m", [C.MESSAGING])],
            [("in", "g"), ("g", "m")],
        ),
    },
    "FS-UNTRUSTED-HTTP-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("out", [C.OUTBOUND_HTTP])], [("in", "out")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.INPUT_VALIDATION]), ("out", [C.OUTBOUND_HTTP])],
            [("in", "g"), ("g", "out")],
        ),
    },
    "FS-FILEREAD-EXFIL-001": {
        "vuln": _graph([("fr", [C.FILE_READ]), ("out", [C.OUTBOUND_HTTP])], [("fr", "out")]),
        "safe": _graph(
            [("fr", [C.FILE_READ]), ("g", [C.OUTPUT_VALIDATION]), ("out", [C.OUTBOUND_HTTP])],
            [("fr", "g"), ("g", "out")],
        ),
    },
    "FS-WEBFETCH-STATECHANGE-001": {
        "vuln": _graph([("f", [C.WEB_FETCH]), ("x", [C.STATE_CHANGE])], [("f", "x")]),
        "safe": _graph(
            [("f", [C.WEB_FETCH]), ("g", [C.OUTPUT_VALIDATION]), ("x", [C.STATE_CHANGE])],
            [("f", "g"), ("g", "x")],
        ),
    },
    "FS-SUBFLOW-UNTRUSTED-001": {
        "vuln": _graph([("in", [C.UNTRUSTED_INPUT]), ("sf", [C.SUBFLOW])], [("in", "sf")]),
        "safe": _graph(
            [("in", [C.UNTRUSTED_INPUT]), ("g", [C.INPUT_VALIDATION]), ("sf", [C.SUBFLOW])],
            [("in", "g"), ("g", "sf")],
        ),
    },
    "FS-SENSITIVE-SUBFLOW-001": {
        "vuln": _graph([("kb", [C.SENSITIVE_DATA]), ("sf", [C.SUBFLOW])], [("kb", "sf")]),
        "safe": _graph([("kb", [C.SENSITIVE_DATA]), ("sf", [C.SUBFLOW])], []),
    },
    # --- structural ---
    "FS-WEBHOOK-UNAUTH-001": {
        "vuln": _graph([("hook", [C.UNTRUSTED_INPUT, C.STATE_CHANGE])], []),
        "safe": _graph([("hook", [C.UNTRUSTED_INPUT, C.STATE_CHANGE, C.AUTHENTICATION])], []),
    },
    "FS-HARDCODED-SECRET-001": {
        "vuln": _graph([("k", [C.SECRETS])], []),
        "safe": _graph([("k", [C.LLM])], []),
    },
    "FS-OVERBROAD-CODE-TOOL-001": {
        "vuln": _graph([("t", [C.CODE_EXECUTION])], []),
        "safe": _graph([("t", [C.WEB_FETCH])], []),
    },
    "FS-OVERBROAD-SQL-TOOL-001": {
        "vuln": _graph([("t", [C.SQL_EXECUTION])], []),
        "safe": _graph([("t", [C.SENSITIVE_DATA])], []),
    },
    "FS-DESERIALIZE-NODE-001": {
        "vuln": _graph([("d", [C.DESERIALIZATION])], []),
        "safe": _graph([("d", [C.LLM])], []),
    },
}


def test_every_rule_has_a_fixture() -> None:
    assert set(FIXTURES) == set(_BY_ID), (
        f"missing: {set(_BY_ID) - set(FIXTURES)}; extra: {set(FIXTURES) - set(_BY_ID)}"
    )


@pytest.mark.parametrize("rule_id", sorted(FIXTURES))
def test_true_positive(rule_id: str) -> None:
    findings = analyze(FIXTURES[rule_id]["vuln"], [_BY_ID[rule_id]])
    assert any(f.rule_id == rule_id for f in findings), f"{rule_id} did not fire on its vuln graph"


@pytest.mark.parametrize("rule_id", sorted(FIXTURES))
def test_false_positive(rule_id: str) -> None:
    findings = analyze(FIXTURES[rule_id]["safe"], [_BY_ID[rule_id]])
    assert not any(f.rule_id == rule_id for f in findings), f"{rule_id} fired on its safe graph"


def test_pack_size_and_severity_mix() -> None:
    assert len(RULES) >= 25
    severities = {r.severity.value for r in RULES}
    assert {"critical", "high", "medium", "low"} <= severities

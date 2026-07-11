import pytest
from pydantic import ValidationError

from flowspect.ir import Capability, Node
from flowspect.rules import RuleLoadError, load_rules_text
from flowspect.rules.schema import NodeMatcher, Rule, Severity


def _node(node_type: str, *caps: Capability, **config: object) -> Node:
    return Node(id="n", type=node_type, capabilities=frozenset(caps), config=config)


# --- NodeMatcher ---------------------------------------------------------


def test_matcher_capability() -> None:
    m = NodeMatcher(capability=Capability.CODE_EXECUTION)
    assert m.matches(_node("x", Capability.CODE_EXECUTION))
    assert not m.matches(_node("x", Capability.LLM))


def test_matcher_any_and_all() -> None:
    any_m = NodeMatcher(any_capabilities=(Capability.OUTBOUND_HTTP, Capability.MESSAGING))
    assert any_m.matches(_node("x", Capability.MESSAGING))
    assert not any_m.matches(_node("x", Capability.LLM))
    all_m = NodeMatcher(all_capabilities=(Capability.LLM, Capability.SECRETS))
    assert all_m.matches(_node("x", Capability.LLM, Capability.SECRETS))
    assert not all_m.matches(_node("x", Capability.LLM))


def test_matcher_type_and_regex_and_config() -> None:
    assert NodeMatcher(type_equals="Webhook").matches(_node("Webhook"))
    assert NodeMatcher(type_regex="(?i)python").matches(_node("PythonREPL"))
    assert NodeMatcher(config_equals={"method": "POST"}).matches(_node("X", method="POST"))
    assert not NodeMatcher(config_equals={"method": "POST"}).matches(_node("X", method="GET"))


def test_matcher_negate() -> None:
    m = NodeMatcher(capability=Capability.AUTHENTICATION, negate=True)
    assert m.matches(_node("x"))  # lacks auth
    assert not m.matches(_node("x", Capability.AUTHENTICATION))


def test_matcher_and_semantics() -> None:
    m = NodeMatcher(type_regex="(?i)http", capability=Capability.OUTBOUND_HTTP)
    assert m.matches(_node("HttpRequest", Capability.OUTBOUND_HTTP))
    assert not m.matches(_node("HttpRequest", Capability.WEB_FETCH))  # wrong cap


def test_empty_matcher_rejected() -> None:
    with pytest.raises(ValidationError, match="at least one constraint"):
        NodeMatcher()


def test_bad_regex_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid type_regex"):
        NodeMatcher(type_regex="(unclosed")


# --- Rule shape ----------------------------------------------------------


def test_taint_rule_needs_source_and_sink() -> None:
    with pytest.raises(ValidationError, match="requires 'source' and 'sink'"):
        Rule(
            id="X-1",
            kind="taint",
            severity=Severity.HIGH,
            title="t",
            source=NodeMatcher(capability=Capability.UNTRUSTED_INPUT),
        )


def test_structural_rule_needs_match() -> None:
    with pytest.raises(ValidationError, match="requires 'match'"):
        Rule(id="X-2", kind="structural", severity=Severity.LOW, title="t")


def test_structural_match_only_is_flag_all() -> None:
    # neither require nor forbid: every matched node is a finding
    rule = Rule(
        id="X-3",
        kind="structural",
        severity=Severity.LOW,
        title="t",
        match=NodeMatcher(capability=Capability.UNTRUSTED_INPUT),
    )
    assert rule.require is None and rule.forbid is None


def test_structural_rule_rejects_both_require_and_forbid() -> None:
    with pytest.raises(ValidationError, match="use at most one"):
        Rule(
            id="X-3B",
            kind="structural",
            severity=Severity.LOW,
            title="t",
            match=NodeMatcher(capability=Capability.UNTRUSTED_INPUT),
            require=NodeMatcher(capability=Capability.AUTHENTICATION),
            forbid=NodeMatcher(capability=Capability.SECRETS),
        )


def test_wrong_fields_for_kind_rejected() -> None:
    with pytest.raises(ValidationError, match="must not set"):
        Rule(
            id="X-4",
            kind="taint",
            severity=Severity.LOW,
            title="t",
            source=NodeMatcher(capability=Capability.UNTRUSTED_INPUT),
            sink=NodeMatcher(capability=Capability.CODE_EXECUTION),
            match=NodeMatcher(capability=Capability.LLM),
        )


def test_bad_id_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule(
            id="lower-case",
            kind="structural",
            severity=Severity.LOW,
            title="t",
            match=NodeMatcher(capability=Capability.LLM),
            forbid=NodeMatcher(capability=Capability.SECRETS),
        )


def test_severity_rank_orders() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank


# --- Loader --------------------------------------------------------------


def test_load_single_and_list() -> None:
    single = load_rules_text(
        "id: A-1\nkind: structural\nseverity: low\ntitle: t\n"
        "match: {capability: llm}\nforbid: {capability: secrets}\n"
    )
    assert len(single) == 1
    listed = load_rules_text(
        "rules:\n"
        "  - {id: A-1, kind: structural, severity: low, title: t,"
        " match: {capability: llm}, forbid: {capability: secrets}}\n"
        "  - {id: A-2, kind: taint, severity: high, title: t,"
        " source: {capability: untrusted_input}, sink: {capability: code_execution}}\n"
    )
    assert [r.id for r in listed] == ["A-1", "A-2"]


def test_loader_aggregates_errors() -> None:
    with pytest.raises(RuleLoadError) as exc:
        load_rules_text(
            "rules:\n"
            "  - {id: B-1, kind: taint, severity: high, title: t}\n"  # missing source/sink
            "  - {id: B-2, kind: structural, severity: nope, title: t,"
            " match: {capability: llm}, forbid: {capability: secrets}}\n"  # bad severity
        )
    assert len(exc.value.errors) >= 2


def test_loader_bad_yaml() -> None:
    with pytest.raises(RuleLoadError, match="invalid YAML"):
        load_rules_text("::: not yaml :::")


def test_loader_empty_is_no_rules() -> None:
    assert load_rules_text("") == []

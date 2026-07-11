import json
from pathlib import Path

from flowspect.reporters import to_json, to_sarif
from flowspect.rules import load_builtin_rules
from flowspect.rules.schema import Severity
from flowspect.scanner import ScanResult, scan_paths

FIXTURES = Path(__file__).parent / "fixtures"
SUPPORT_AGENT = FIXTURES / "langflow" / "support-agent.json"


def _result() -> ScanResult:
    return scan_paths([SUPPORT_AGENT], load_builtin_rules())


def test_scan_file_finds_criticals() -> None:
    result = _result()
    assert len(result.scanned_files) == 1
    assert result.max_severity() is Severity.CRITICAL
    assert result.counts()[Severity.CRITICAL] == 2


def test_scan_directory_skips_non_flows(tmp_path: Path) -> None:
    (tmp_path / "noise.json").write_text('{"unrelated": true}')
    (tmp_path / "flow.json").write_text(SUPPORT_AGENT.read_text())
    result = scan_paths([tmp_path], load_builtin_rules())
    assert len(result.scanned_files) == 1
    assert not result.errors


def test_scan_missing_path_reports_error(tmp_path: Path) -> None:
    result = scan_paths([tmp_path / "ghost.json"], load_builtin_rules())
    assert result.errors
    assert "does not exist" in result.errors[0].message


def test_scan_direct_unparseable_file_is_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a known flow"}')
    result = scan_paths([bad], load_builtin_rules())
    assert result.errors
    assert result.findings == ()


def test_json_reporter_valid_and_complete() -> None:
    payload = json.loads(to_json(_result()))
    assert payload["tool"] == "flowspect"
    assert payload["summary"]["findings"] == 2
    assert payload["summary"]["by_severity"]["critical"] == 2
    first = payload["findings"][0]
    assert first["path"][0] == "ChatInput-b6UCc"
    assert first["remediation"]


def test_sarif_reporter_shape() -> None:
    doc = json.loads(to_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "flowspect"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "FS-TRIFECTA-001" in rule_ids
    result0 = run["results"][0]
    assert result0["level"] == "error"
    assert result0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(
        "support-agent.json"
    )
    # security-severity present for GitHub ranking
    desc = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == result0["ruleId"])
    assert "security-severity" in desc["properties"]


def test_sarif_codeflow_names_each_node() -> None:
    doc = json.loads(to_sarif(_result()))
    flow = doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    names = [loc["location"]["logicalLocations"][0]["name"] for loc in flow]
    assert names[0] == "Customer Message"
    assert len(names) == 4


def test_sarif_empty_result_is_valid() -> None:
    empty = scan_paths([], [])
    doc = json.loads(to_sarif(empty))
    assert doc["runs"][0]["results"] == []

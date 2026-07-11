import json
from pathlib import Path

from typer.testing import CliRunner

from flowspect.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
SUPPORT_AGENT = FIXTURES / "langflow" / "support-agent.json"

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "flowspect" in result.stdout


def test_scan_table_exits_nonzero_on_findings() -> None:
    result = runner.invoke(app, ["scan", str(SUPPORT_AGENT)])
    assert result.exit_code == 1
    assert "FS-TRIFECTA-001" in result.stdout


def test_scan_json_output() -> None:
    result = runner.invoke(app, ["scan", str(SUPPORT_AGENT), "-f", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings"] == 2


def test_scan_sarif_output() -> None:
    result = runner.invoke(app, ["scan", str(SUPPORT_AGENT), "-f", "sarif"])
    assert result.exit_code == 1
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"


def test_scan_fail_on_threshold_above_findings() -> None:
    # findings are critical; a table scan with --fail-on critical still exits 1
    crit = runner.invoke(app, ["scan", str(SUPPORT_AGENT), "--fail-on", "critical"])
    assert crit.exit_code == 1


def test_scan_output_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(SUPPORT_AGENT), "-f", "json", "-o", str(out)])
    assert result.exit_code == 1
    assert json.loads(out.read_text())["summary"]["findings"] == 2


def test_scan_clean_flow_exits_zero(tmp_path: Path) -> None:
    safe = tmp_path / "safe.json"
    safe.write_text(
        json.dumps(
            {
                "name": "Safe",
                "data": {
                    "nodes": [
                        {
                            "id": "ChatInput-1",
                            "data": {"type": "ChatInput", "node": {"template": {}}},
                        },
                        {
                            "id": "ChatOutput-1",
                            "data": {"type": "ChatOutput", "node": {"template": {}}},
                        },
                    ],
                    "edges": [{"source": "ChatInput-1", "target": "ChatOutput-1", "data": {}}],
                },
            }
        )
    )
    result = runner.invoke(app, ["scan", str(safe)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_rules_command_lists_builtins() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "FS-TRIFECTA-001" in result.stdout


def test_bad_rules_path_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("id: nope\nkind: taint\n")  # invalid rule
    result = runner.invoke(app, ["scan", str(SUPPORT_AGENT), "-r", str(bad)])
    assert result.exit_code == 2

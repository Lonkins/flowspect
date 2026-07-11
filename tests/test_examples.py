"""The shipped example projects are part of the contract: the vulnerable one
must flag the planted classes with correct paths; the safe one must be clean."""

from pathlib import Path

from flowspect.rules import load_builtin_rules
from flowspect.rules.schema import Severity
from flowspect.scanner import scan_paths

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_vulnerable_example_flags_planted_findings() -> None:
    result = scan_paths([EXAMPLES / "vulnerable-langflow"], load_builtin_rules())
    by_id = {f.rule_id: f for f in result.findings}

    assert "FS-INJECT-EXEC-001" in by_id
    assert by_id["FS-INJECT-EXEC-001"].path_labels == (
        "Customer Chat",
        "Compose Prompt",
        "Support Agent",
        "Python Tool",
    )

    assert "FS-TRIFECTA-001" in by_id
    assert by_id["FS-TRIFECTA-001"].path_labels[-1] == "CRM Update"

    assert "FS-HARDCODED-SECRET-001" in by_id
    assert result.max_severity() is Severity.CRITICAL


def test_safe_example_is_clean() -> None:
    result = scan_paths([EXAMPLES / "safe-langflow"], load_builtin_rules())
    assert result.findings == ()
    assert len(result.scanned_files) == 1


def test_skip_unrecognized_suppresses_named_nonflow_errors(tmp_path: Path) -> None:
    junk = tmp_path / "config.json"
    junk.write_text('{"just": "config"}')
    with_error = scan_paths([junk], load_builtin_rules())
    assert with_error.errors
    skipped = scan_paths([junk], load_builtin_rules(), skip_unrecognized=True)
    assert not skipped.errors

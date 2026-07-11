"""Guard the generated rule catalog against drift."""

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent.parent / "scripts" / "gen_rule_catalog.py"


def _load_generator() -> object:
    spec = importlib.util.spec_from_file_location("gen_rule_catalog", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_rule_catalog"] = module
    spec.loader.exec_module(module)
    return module


def test_rule_catalog_is_up_to_date() -> None:
    gen = _load_generator()
    generated = gen.render()  # type: ignore[attr-defined]
    committed = gen.output_path().read_text(encoding="utf-8")  # type: ignore[attr-defined]
    assert generated == committed, (
        "docs/rules.md is stale — run: python scripts/gen_rule_catalog.py"
    )

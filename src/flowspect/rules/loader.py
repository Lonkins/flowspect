"""Load and validate rule YAML into :class:`Rule` objects.

A rule file is either a single mapping or a ``{"rules": [...]}`` list. Validation
errors are aggregated and raised as one :class:`RuleLoadError` so authors see
every problem at once, not one per run.
"""

from pathlib import Path

import yaml
from pydantic import ValidationError

from flowspect.rules.schema import Rule


class RuleLoadError(Exception):
    """One or more rules failed to parse or validate."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("failed to load rules:\n  - " + "\n  - ".join(errors))


def _raw_rules(data: object, origin: str) -> list[tuple[dict[str, object], str]]:
    if isinstance(data, dict) and "rules" in data:
        rules = data["rules"]
        if not isinstance(rules, list):
            raise RuleLoadError([f"{origin}: 'rules' must be a list"])
        return [(r, origin) for r in rules if isinstance(r, dict)]
    if isinstance(data, dict):
        return [(data, origin)]  # single-rule file
    if isinstance(data, list):
        return [(r, origin) for r in data if isinstance(r, dict)]
    raise RuleLoadError([f"{origin}: expected a rule mapping or a list of rules"])


def load_rules_text(text: str, *, origin: str = "<string>") -> list[Rule]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleLoadError([f"{origin}: invalid YAML: {exc}"]) from exc
    if data is None:
        return []

    rules: list[Rule] = []
    errors: list[str] = []
    for raw, where in _raw_rules(data, origin):
        rid = raw.get("id", "<no id>")
        try:
            rules.append(Rule.model_validate(raw))
        except ValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(p) for p in err["loc"]) or "<root>"
                errors.append(f"{where}: rule {rid!r}: {loc}: {err['msg']}")
    if errors:
        raise RuleLoadError(errors)
    return rules


def load_rules_file(path: Path) -> list[Rule]:
    return load_rules_text(path.read_text(encoding="utf-8"), origin=str(path))


def load_rules_dir(directory: Path) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` under ``directory``; duplicate ids are an error."""
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.suffix not in {".yml", ".yaml"} or not path.is_file():
            continue
        try:
            for rule in load_rules_file(path):
                if rule.id in seen:
                    errors.append(f"duplicate rule id {rule.id!r} ({seen[rule.id]} and {path})")
                else:
                    seen[rule.id] = str(path)
                    rules.append(rule)
        except RuleLoadError as exc:
            errors.extend(exc.errors)
    if errors:
        raise RuleLoadError(errors)
    return rules


def load_builtin_rules() -> list[Rule]:
    """Load the bundled rule pack shipped in ``flowspect/rules/builtin``."""
    return load_rules_dir(Path(__file__).parent / "builtin")

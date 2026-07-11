"""Rule DSL: schema, loader, and the bundled rule pack."""

from flowspect.rules.loader import (
    RuleLoadError,
    load_builtin_rules,
    load_rules_dir,
    load_rules_file,
    load_rules_text,
)
from flowspect.rules.schema import NodeMatcher, Rule, Severity

__all__ = [
    "NodeMatcher",
    "Rule",
    "RuleLoadError",
    "Severity",
    "load_builtin_rules",
    "load_rules_dir",
    "load_rules_file",
    "load_rules_text",
]

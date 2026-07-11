"""Rule DSL schema — pydantic models for authored YAML rules.

Two rule kinds:

* **taint** — asserts there is no unsanitised data-flow path from a ``source``
  node class to a ``sink`` node class. Optional gates sharpen the assertion:
  ``sanitizer`` (a matcher that neutralises the flow), ``also_reachable_from``
  (the sink must additionally be taint-reachable from a second class — this is
  how the lethal trifecta requires sensitive data to converge on the exfil sink),
  and ``path_contains`` (the tainted path must pass through a matching node).

* **structural** — a per-node predicate. ``match`` selects candidate nodes;
  each must satisfy ``require`` (else it's a finding) or must *not* match
  ``forbid`` (else it's a finding).

A ``NodeMatcher`` is an AND of whatever constraints are set. Every field is
optional; an empty matcher matches nothing (guarded at load time).
"""

import re
from enum import IntEnum, StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from flowspect.ir import Capability, Node


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


class _Rank(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: _Rank.CRITICAL,
    Severity.HIGH: _Rank.HIGH,
    Severity.MEDIUM: _Rank.MEDIUM,
    Severity.LOW: _Rank.LOW,
}


class NodeMatcher(BaseModel):
    """A predicate over a single IR node. Set fields are AND-ed together."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: Capability | None = None
    any_capabilities: tuple[Capability, ...] = ()
    all_capabilities: tuple[Capability, ...] = ()
    type_equals: str | None = None
    type_regex: str | None = None
    config_equals: dict[str, JsonValue] = Field(default_factory=dict)
    negate: bool = False  # invert the whole matcher

    @model_validator(mode="after")
    def _non_empty(self) -> "NodeMatcher":
        if not any(
            (
                self.capability is not None,
                self.any_capabilities,
                self.all_capabilities,
                self.type_equals is not None,
                self.type_regex is not None,
                self.config_equals,
            )
        ):
            raise ValueError("node matcher must declare at least one constraint")
        if self.type_regex is not None:
            try:
                re.compile(self.type_regex)
            except re.error as exc:
                raise ValueError(f"invalid type_regex: {exc}") from exc
        return self

    def matches(self, node: Node) -> bool:
        result = self._matches_core(node)
        return not result if self.negate else result

    def _matches_core(self, node: Node) -> bool:
        if self.capability is not None and self.capability not in node.capabilities:
            return False
        if self.any_capabilities and node.capabilities.isdisjoint(self.any_capabilities):
            return False
        if self.all_capabilities and not set(self.all_capabilities) <= node.capabilities:
            return False
        if self.type_equals is not None and node.type != self.type_equals:
            return False
        if self.type_regex is not None and not re.search(self.type_regex, node.type):
            return False
        return all(node.config.get(key) == expected for key, expected in self.config_equals.items())


class Rule(BaseModel):
    """One compiled rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9\-]*$")
    kind: Literal["taint", "structural"]
    severity: Severity
    title: str
    description: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()

    # taint fields
    source: NodeMatcher | None = None
    sink: NodeMatcher | None = None
    sanitizer: NodeMatcher | None = None
    also_reachable_from: NodeMatcher | None = None
    path_contains: NodeMatcher | None = None

    # structural fields
    match: NodeMatcher | None = None
    require: NodeMatcher | None = None
    forbid: NodeMatcher | None = None

    @model_validator(mode="after")
    def _kind_shape(self) -> "Rule":
        if self.kind == "taint":
            if self.source is None or self.sink is None:
                raise ValueError(f"taint rule {self.id!r} requires 'source' and 'sink'")
            _reject(self.id, "taint", match=self.match, require=self.require, forbid=self.forbid)
        else:  # structural
            if self.match is None:
                raise ValueError(f"structural rule {self.id!r} requires 'match'")
            if (self.require is None) == (self.forbid is None):
                raise ValueError(
                    f"structural rule {self.id!r} requires exactly one of 'require' or 'forbid'"
                )
            _reject(
                self.id,
                "structural",
                source=self.source,
                sink=self.sink,
                sanitizer=self.sanitizer,
                also_reachable_from=self.also_reachable_from,
                path_contains=self.path_contains,
            )
        return self


def _reject(rule_id: str, kind: str, **fields: NodeMatcher | None) -> None:
    stray = [name for name, value in fields.items() if value is not None]
    if stray:
        raise ValueError(f"{kind} rule {rule_id!r} must not set: {', '.join(sorted(stray))}")

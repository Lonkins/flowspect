"""SARIF 2.1.0 reporter — for GitHub code scanning.

Each finding becomes a result with a ``codeFlows`` entry naming every node on the
tainted path (as logical locations), so the graph flow is visible in the code
scanning UI. Rule metadata is emitted once in ``tool.driver.rules``. Flow export
files have no meaningful line numbers, so physical locations anchor to line 1 of
the file — GitHub requires a region, and file-level annotation is the honest
granularity for a graph export.
"""

import hashlib
import json

from flowspect import __version__
from flowspect.analysis import Finding
from flowspect.rules.schema import Severity
from flowspect.scanner import ScanResult

_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_INFO_URI = "https://github.com/Lonkins/flowspect"

# SARIF level + GitHub security-severity (0-10) per flowspect severity.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


def _fingerprint(finding: Finding) -> str:
    raw = f"{finding.rule_id}:{finding.source_path}:{'>'.join(finding.path)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _rule_descriptor(finding: Finding) -> dict[str, object]:
    descriptor: dict[str, object] = {
        "id": finding.rule_id,
        "name": "".join(part.capitalize() for part in finding.rule_id.split("-")),
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", finding.source_format],
        },
    }
    if finding.remediation:
        descriptor["fullDescription"] = {"text": finding.remediation}
        descriptor["help"] = {"text": finding.remediation}
    if finding.references:
        descriptor["helpUri"] = finding.references[0]
    return descriptor


def _location(finding: Finding, node_id: str, label: str) -> dict[str, object]:
    location: dict[str, object] = {
        "logicalLocations": [{"name": label, "fullyQualifiedName": node_id, "kind": "component"}],
    }
    if finding.source_path:
        location["physicalLocation"] = {
            "artifactLocation": {"uri": finding.source_path},
            "region": {"startLine": 1},
        }
    return location


def _result(finding: Finding) -> dict[str, object]:
    flow_locations = [
        {"location": _location(finding, node_id, label)}
        for node_id, label in zip(finding.path, finding.path_labels, strict=True)
    ]
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": _result_message(finding)},
        "locations": [_location(finding, finding.primary_node, finding.path_labels[-1])],
        "codeFlows": [{"threadFlows": [{"locations": flow_locations}]}],
        "partialFingerprints": {"flowspect/v1": _fingerprint(finding)},
    }


def _result_message(finding: Finding) -> str:
    text = finding.message
    if finding.remediation:
        text += f"\n\nRemediation: {finding.remediation}"
    return text


def to_sarif(result: ScanResult, *, indent: int | None = 2) -> str:
    # Deduplicate rule descriptors, keeping first occurrence order.
    descriptors: dict[str, dict[str, object]] = {}
    for finding in result.findings:
        descriptors.setdefault(finding.rule_id, _rule_descriptor(finding))

    sarif = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "flowspect",
                        "version": __version__,
                        "informationUri": _INFO_URI,
                        "rules": list(descriptors.values()),
                    }
                },
                "results": [_result(f) for f in result.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=indent)

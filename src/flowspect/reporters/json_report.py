"""JSON reporter — machine-readable scan output."""

import json

from flowspect.scanner import ScanResult


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    payload = {
        "version": "1.0",
        "tool": "flowspect",
        "summary": {
            "files_scanned": len(result.scanned_files),
            "graphs_analyzed": len(result.graphs),
            "findings": len(result.findings),
            "by_severity": {sev.value: count for sev, count in result.counts().items()},
            "errors": len(result.errors),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "message": f.message,
                "graph": f.graph_name,
                "source_format": f.source_format,
                "file": f.source_path,
                "path": list(f.path),
                "path_labels": list(f.path_labels),
                "primary_node": f.primary_node,
                "remediation": f.remediation,
                "references": list(f.references),
            }
            for f in result.findings
        ],
        "errors": [{"path": e.path, "message": e.message} for e in result.errors],
    }
    return json.dumps(payload, indent=indent)

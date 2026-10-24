"""JSON report (schema ``1.0``).

The document is designed to be diffed between assessments: arrays are sorted
deterministically, relationship-type counts are key-sorted, and finding ids are
derived from their evidence chain. Only the ``generated_at`` timestamp (and any
timestamp inside the source export) varies between identical runs.

Deliberately excluded: object attribute values (descriptions, script paths,
OS build strings) and every credential or authentication artefact. The graph is
summarised by counts and typed relationships, not by copying the directory.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .. import SCHEMA_VERSION, TOOL_NAME, __version__
from ..analysis import AnalysisResult
from ..models import Severity

EXCLUDED_DATA = [
    "object attribute values (descriptions, scripts, operating system build strings)",
    "passwords, password hashes, Kerberos keys and any credential material",
    "authentication secrets (bind passwords, tokens, keytab contents)",
]


def render(
    result: AnalysisResult,
    generated_at: Optional[str] = None,
    verbose: bool = False,
) -> str:
    payload = build(result, generated_at=generated_at, verbose=verbose)
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def build(
    result: AnalysisResult,
    generated_at: Optional[str] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    dataset = result.dataset
    collection = dataset.collection
    labels = result.labels

    relationship_types: Dict[str, int] = {}
    for edge in dataset.edges:
        relationship_types[edge.type] = relationship_types.get(edge.type, 0) + 1

    findings = [
        finding.to_dict(labels)
        for finding in result.findings
        if verbose or finding.severity is not Severity.INFO
    ]
    counts = {severity.value: 0 for severity in Severity}
    for finding in result.findings:
        if verbose or finding.severity is not Severity.INFO:
            counts[finding.severity.value] += 1

    paths = [
        path.to_dict(labels)
        for path in result.search.paths
    ]

    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assessment": {
            "target_domain": collection.target_domain,
            "mode": collection.mode,
            "format": collection.format,
            "inputs": list(collection.inputs),
            "collected_at": collection.collected_at,
            "complete": collection.complete,
        },
        "collection": {
            "objects": dataset.object_type_counts(),
            "object_total": len(dataset.objects),
            "relationships": len(dataset.edges),
            "relationship_types": {name: relationship_types[name] for name in sorted(relationship_types)},
            "issues": [issue.to_dict() for issue in _sorted_issues(dataset.issues)],
            "gaps": sorted(collection.gaps),
        },
        "analysis": {
            "graph": {"nodes": len(result.graph.nodes), "relationships": result.graph.edge_count},
            "configuration": {
                "max_depth": result.config.max_depth,
                "max_paths": result.config.max_paths,
                "max_sources": result.config.max_sources,
                "max_paths_per_pair": result.config.max_paths_per_pair,
                "expansion_budget": result.config.budget,
                "start_principals": list(result.config.starts),
                "requested_targets": list(result.config.targets),
                "include_default_targets": result.config.include_default_targets,
            },
            "search": result.search.to_dict(),
            "sources_analysed": len(result.sources),
            "sources": [labels.get(source, source) for source in sorted(result.sources)],
            "targets": [target.to_dict() for target in result.resolution.targets],
            "targets_without_evidence": _targets_without_evidence(result),
        },
        "summary": {
            "total": sum(counts.values()),
            "critical": counts[Severity.CRITICAL.value],
            "high": counts[Severity.HIGH.value],
            "medium": counts[Severity.MEDIUM.value],
            "low": counts[Severity.LOW.value],
            "info": counts[Severity.INFO.value],
        },
        "findings": findings,
        "privilege_paths": paths,
        "limitations": _unique(result.limitations),
        "notes": _unique(result.notes),
        "excluded_data": list(EXCLUDED_DATA),
    }
    return payload


def _targets_without_evidence(result: AnalysisResult) -> List[Dict[str, Any]]:
    """Targets that have no inbound relationship at all.

    This is a data-completeness signal, not a "clean" verdict: a target with no
    inbound edges may simply be an object whose ACLs were never collected.
    """
    missing: List[Dict[str, Any]] = []
    for target in result.resolution.targets:
        if result.graph.incoming(target.id):
            continue
        missing.append(
            {
                "id": target.id,
                "label": target.label,
                "reason": "no inbound relationships were collected",
            }
        )
    return missing


def _sorted_issues(issues) -> List[Any]:
    return sorted(issues, key=lambda issue: (issue.code, issue.message, issue.reference))


def _unique(values: List[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result

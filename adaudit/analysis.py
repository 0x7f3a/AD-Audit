"""Analysis orchestration and the finding engine.

The engine turns *potential privilege paths* into evidence-backed findings. Two
rules shape every finding:

1. Severity and confidence are independent. A path to a tier-0 target is
   severe even when the supporting data is incomplete, and the report says so.
2. A finding states only what the data shows. It never asserts that an attack
   succeeds, only which relationships were collected and why they matter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .graph import DirectoryGraph, PathSearchResult
from .models import (
    Confidence,
    DirObject,
    DirectoryDataset,
    Edge,
    EvidenceQuality,
    Finding,
    ObjectType,
    PrivilegePath,
    Severity,
    stable_finding_id,
)
from .relationships import (
    CONTROL_RELATIONSHIPS,
    edge_category,
    edge_prerequisites,
    edge_remediation,
    edge_weight,
)
from .targets import Target, TargetResolution, resolve_targets
from .normalize import dn_key, normalise_sid, split_identifier

DATA_GAP_CHECK = "AD-DATA"
PATH_CHECK = "AD-PATH"

_REFERENCES = [
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
    "security-best-practices/best-practices-for-securing-active-directory",
    "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html",
]

_CATEGORY_REFERENCES: Dict[str, List[str]] = {
    "replication": [
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "advanced-features/managing-roles-based-access-control",
    ],
    "gpo": [
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/"
        "jj574467(v=ws.11)",
    ],
}

_GLOBAL_LIMITATION = (
    "Effective access was not verified: permissions are evaluated as collected, "
    "without expanding group membership, deny ACEs, or control-access checks on "
    "the target object."
)

_NO_EXPLOIT_LIMITATION = (
    "No authentication or exploitation was attempted. Every step lists its "
    "prerequisites and must be verified before it is treated as reachable."
)


@dataclass
class AnalysisConfig:
    """Every knob that changes analysis results is recorded in the report."""

    max_depth: int = 6
    max_paths: int = 50
    max_sources: int = 500
    max_paths_per_pair: int = 3
    budget: int = 200_000
    starts: Sequence[str] = ()
    targets: Sequence[str] = ()
    include_default_targets: bool = True


@dataclass
class AnalysisResult:
    dataset: DirectoryDataset
    graph: DirectoryGraph
    config: AnalysisConfig
    resolution: TargetResolution
    search: PathSearchResult
    sources: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    skipped_sources: List[str] = field(default_factory=list)
    pruned_paths: int = 0

    @property
    def labels(self) -> Dict[str, str]:
        return self.graph.labels()

    def severity_counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def severity_counts_visible(self, verbose: bool) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            if not verbose and finding.severity is Severity.INFO:
                continue
            counts[finding.severity.value] += 1
        return counts

    def target_member_summary(self) -> List[Tuple[Target, int]]:
        summary: List[Tuple[Target, int]] = []
        for target in self.resolution.targets:
            summary.append((target, self.graph.direct_member_count(target.id)))
        summary.sort(key=lambda item: (item[0].tier, -item[1], item[0].label))
        return summary


def analyse(dataset: DirectoryDataset, config: Optional[AnalysisConfig] = None) -> AnalysisResult:
    config = config or AnalysisConfig()
    graph = DirectoryGraph(dataset)
    resolution = resolve_targets(
        dataset,
        cli_targets=config.targets,
        include_defaults=config.include_default_targets,
    )

    notes: List[str] = list(resolution.notes)
    limitations: List[str] = []

    sources, source_notes, skipped = _resolve_sources(dataset, graph, config, resolution)
    notes.extend(source_notes)

    target_ids = resolution.ids
    if not target_ids:
        limitations.append(
            "No privileged targets were resolved, so no path analysis was performed."
        )
        return _finalise(
            AnalysisResult(
                dataset=dataset,
                graph=graph,
                config=config,
                resolution=resolution,
                search=PathSearchResult(),
                sources=sources,
                limitations=limitations,
                notes=notes,
                skipped_sources=skipped,
            )
        )

    search = graph.find_paths(
        sources,
        target_ids,
        max_depth=config.max_depth,
        max_paths=config.max_paths,
        budget=config.budget,
    )
    if search.missing_sources:
        notes.append(
            "Starting principals not found in the dataset: "
            + ", ".join(sorted(search.missing_sources))
        )
    if search.stats.truncated:
        limitations.append(
            "Path search was truncated: " + (search.stats.truncation_reason or "limit reached")
        )

    findings: List[Finding] = []
    seen_ids: Dict[str, Finding] = {}
    pair_counts: Dict[Tuple[str, str], int] = {}
    pruned = 0
    targets_by_id = resolution.by_id()

    for path in search.paths:
        pairs = pair_counts.get((path.source, path.target), 0)
        if pairs >= config.max_paths_per_pair:
            pruned += 1
            continue
        pair_counts[(path.source, path.target)] = pairs + 1
        target = targets_by_id[path.target]
        finding = _path_finding(path, graph, target)
        existing = seen_ids.get(finding.id)
        if existing is not None:
            # Same relationship chain reached through duplicate records.
            continue
        seen_ids[finding.id] = finding
        findings.append(finding)

    if pruned:
        limitations.append(
            f"{pruned} additional path(s) between the same pair of objects were "
            "omitted for readability (--max-paths-per-pair)."
        )

    gap_finding = _data_gap_finding(dataset, search)
    if gap_finding is not None:
        findings.append(gap_finding)

    findings.sort(key=lambda finding: finding.sort_key)

    limitations.extend(_dataset_limitations(dataset))

    return _finalise(
        AnalysisResult(
            dataset=dataset,
            graph=graph,
            config=config,
            resolution=resolution,
            search=search,
            sources=sources,
            findings=findings,
            limitations=limitations,
            notes=notes,
            skipped_sources=skipped,
            pruned_paths=pruned,
        )
    )


def _finalise(result: AnalysisResult) -> AnalysisResult:
    for statement in (_GLOBAL_LIMITATION, _NO_EXPLOIT_LIMITATION):
        if statement not in result.limitations:
            result.limitations.insert(0, statement)
    return result


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def _resolve_sources(
    dataset: DirectoryDataset,
    graph: DirectoryGraph,
    config: AnalysisConfig,
    resolution: TargetResolution,
) -> Tuple[List[str], List[str], List[str]]:
    notes: List[str] = []
    target_ids = set(resolution.ids)

    if config.starts:
        resolved: List[str] = []
        missing: List[str] = []
        for token in (spec.strip() for spec in config.starts):
            if not token:
                continue
            matches = _match_principal(dataset, token)
            if not matches:
                missing.append(token)
                continue
            for obj in matches:
                if obj.id not in resolved:
                    resolved.append(obj.id)
        if missing:
            notes.append("Starting principals that matched no object: " + ", ".join(sorted(missing)))
        excluded = [node for node in resolved if node in target_ids]
        if excluded:
            notes.append(
                f"{len(excluded)} requested starting principal(s) are themselves "
                "privileged targets and were not analysed as a path source."
            )
        return sorted(node for node in resolved if node not in target_ids), notes, []

    candidates = [
        obj
        for obj in graph.nodes.values()
        if obj.type in (ObjectType.USER, ObjectType.COMPUTER)
        and obj.id not in target_ids
        and not obj.attributes.get("unresolved")
    ]
    candidates.sort(key=lambda obj: (obj.type.value, obj.label.lower(), obj.id))
    selected = candidates[: config.max_sources]
    skipped = [obj.id for obj in candidates[config.max_sources :]]
    if skipped:
        notes.append(
            f"Only the first {config.max_sources} non-privileged principals were "
            "analysed (--max-sources); use --start to choose explicitly."
        )
    if not selected:
        notes.append(
            "No non-privileged user or computer objects were available as "
            "starting principals; use --start to name one explicitly."
        )
    return [obj.id for obj in selected], notes, skipped


def _match_principal(dataset: DirectoryDataset, token: str) -> List[DirObject]:
    sid = normalise_sid(token)
    if sid:
        return sorted(
            (obj for obj in dataset.objects.values() if obj.sid and obj.sid.upper() == sid),
            key=lambda obj: obj.id,
        )
    domain, name = split_identifier(token)
    lookup = dn_key(name) if "=" in name else name.strip().lower()
    matches: List[DirObject] = []
    for obj in dataset.objects.values():
        values = {
            str(obj.id).lower(),
            (obj.sam or "").lower(),
            obj.name.lower(),
            obj.label.lower(),
        }
        dn_value = dn_key(obj.dn)
        if dn_value:
            values.add(dn_value)
        if lookup in values:
            if domain and obj.domain and not _domain_matches(obj.domain, domain):
                continue
            matches.append(obj)
    return sorted(matches, key=lambda obj: obj.id)


def _domain_matches(object_domain: str, requested: str) -> bool:
    object_domain = object_domain.lower()
    requested = requested.lower()
    return object_domain == requested or object_domain.split(".", 1)[0] == requested


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _path_finding(path: PrivilegePath, graph: DirectoryGraph, target: Target) -> Finding:
    labels = graph.labels()
    source_label = labels.get(path.source, path.source)
    target_label = labels.get(path.target, path.target)

    severity = target.severity_floor
    confidence = path.confidence
    steps = path.steps
    final_edge = steps[-1]

    direct_control = (
        len(steps) == 1
        and final_edge.type in CONTROL_RELATIONSHIPS
        and final_edge.quality is EvidenceQuality.EXPLICIT
    )
    if direct_control:
        severity = severity.upgrade(1)

    has_unresolved_node = False
    for node in path.nodes:
        obj = graph.object_for(node)
        if obj is None or obj.type is ObjectType.UNKNOWN:
            has_unresolved_node = True
            break
    if has_unresolved_node:
        confidence = Confidence.weakest([confidence, Confidence.POSSIBLE])

    if confidence is Confidence.POSSIBLE:
        severity = severity.downgrade(1)

    category = _dominant_category(steps)
    check_id = PATH_CHECK
    title = (
        f"Direct control over privileged target: {target.definition}"
        if direct_control
        else f"Potential path to privileged target: {target.definition}"
    )
    description = (
        f"The collected data connects {source_label} to {target_label} "
        f"({target.definition}) through {len(steps)} relationship"
        f"{'s' if len(steps) != 1 else ''}: "
        + " -> ".join([labels.get(node, node) for node in path.nodes])
        + ". This is a potential privilege path in the modelled data, not a "
        "confirmed exploit."
    )

    evidence: List[Dict[str, object]] = []
    for index, edge in enumerate(steps, start=1):
        step_from = labels.get(edge.source, edge.source)
        step_to = labels.get(edge.target, edge.target)
        for item in edge.evidence:
            evidence.append(
                {
                    "step": index,
                    "relationship": edge.type,
                    "from": step_from,
                    "to": step_to,
                    "quality": item.quality.value,
                    "detail": item.detail,
                    "reference": item.reference,
                }
            )

    prerequisites = _unique(
        edge_prerequisites(edge.type) for edge in steps if edge_prerequisites(edge.type)
    )
    limitations = _path_limitations(path, confidence)
    recommendations = _unique(
        edge_remediation(edge.type) for edge in steps if edge_remediation(edge.type)
    )
    if not recommendations:
        recommendations = [
            "Review the relationship chain and remove any step that is not "
            "required for the business role."
        ]

    if target.object_type == "domain":
        impact = f"{source_label} may be able to gain control of {target_label} ({target.rationale})."
    else:
        impact = (
            f"{source_label} may be able to gain the privileges of {target_label} "
            f"({target.rationale})."
        )
    if len(steps) > 1:
        impact += (
            " Each intermediate step has its own prerequisites, so the chain is "
            "only usable if every step is actually effective."
        )
    if any(step.type == "Session" for step in steps):
        impact += (
            " The chain depends on credential material from a logged-on session "
            "remaining recoverable on the host."
        )

    references = list(_REFERENCES)
    for step in steps:
        references.extend(_CATEGORY_REFERENCES.get(edge_category(step.type), []))
    references = _unique(references)

    return Finding(
        id=stable_finding_id(PATH_CHECK, f"{path.signature}|target={target.id}"),
        title=title,
        severity=severity,
        confidence=confidence,
        category=category,
        description=description,
        check_id=check_id,
        source_objects=[path.source],
        target_objects=[path.target],
        path=path,
        evidence=evidence,
        impact=impact,
        recommendation=" ".join(recommendations),
        limitations=limitations,
        references=references,
        prerequisites=prerequisites,
    )


def _dominant_category(steps: Sequence[Edge]) -> str:
    best_index = 0
    best_weight = -1
    for index, edge in enumerate(steps):
        weight = edge_weight(edge.type)
        if weight >= best_weight:
            best_weight = weight
            best_index = index
    return edge_category(steps[best_index].type)


def _path_limitations(path: PrivilegePath, confidence: Confidence) -> List[str]:
    limitations = [_GLOBAL_LIMITATION, _NO_EXPLOIT_LIMITATION]
    if any(edge.inherited for edge in path.steps):
        limitations.append(
            "At least one step relies on an inherited permission; the modifiable "
            "control point is the parent object that carries the ACE."
        )
    if any(edge.type == "Session" for edge in path.steps):
        limitations.append(
            "Session data reflects the moment of collection and does not prove "
            "that recoverable credential material remains on the host."
        )
    if any(edge.type == "Contains" for edge in path.steps):
        limitations.append(
            "Container influence is inferred from structure: it assumes control "
            "of the container includes changing policy links or object location."
        )
    if confidence is not Confidence.CONFIRMED:
        limitations.append(
            "Part of the chain is derived or unresolved data rather than an "
            "explicitly collected relationship."
        )
    if confidence is Confidence.POSSIBLE:
        limitations.append(
            "This finding is weakly supported; treat it as a lead to verify "
            "rather than a conclusion."
        )
    return limitations


def _data_gap_finding(
    dataset: DirectoryDataset,
    search: PathSearchResult,
) -> Optional[Finding]:
    issues = list(dataset.issues)
    gaps = list(dataset.collection.gaps) + dataset.gap_statements()
    if search.stats.truncated:
        gaps.append("Path search was truncated; the result set is incomplete.")
    if not issues and not gaps:
        return None

    evidence: List[Dict[str, object]] = []
    for issue in issues[:25]:
        evidence.append(
            {
                "relationship": None,
                "detail": f"[{issue.code}] {issue.message}",
                "reference": issue.reference,
                "quality": "observed",
            }
        )
    for gap in gaps[:15]:
        evidence.append({"relationship": None, "detail": gap, "reference": "", "quality": "observed"})
    if len(issues) > 25 or len(gaps) > 15:
        evidence.append(
            {
                "relationship": None,
                "detail": f"{max(0, len(issues) - 25)} further issue(s) and "
                f"{max(0, len(gaps) - 15)} further gap(s) are recorded in the JSON report.",
                "reference": "",
                "quality": "observed",
            }
        )

    description = (
        f"The collected dataset has {len(issues)} import/collection issue(s) and "
        f"{len(gaps)} data gap(s). Relationships that were not collected cannot be "
        "analysed, so the absence of a path is not evidence that no path exists."
    )
    recommendation = (
        "Resolve the listed issues and re-collect with the permissions described "
        "in the documentation, then re-run the analysis."
    )
    return Finding(
        id=f"{DATA_GAP_CHECK}-001",
        title="Collection completeness gaps",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        category="data-quality",
        description=description,
        check_id=DATA_GAP_CHECK,
        source_objects=[],
        target_objects=[],
        path=None,
        evidence=evidence,
        impact=(
            "Incomplete data can hide privilege paths or make a path appear to end "
            "prematurely."
        ),
        recommendation=recommendation,
        limitations=[
            "Only the dataset supplied to this run was evaluated; live directory "
            "state may differ."
        ],
    )


def _dataset_limitations(dataset: DirectoryDataset) -> List[str]:
    limitations = [_GLOBAL_LIMITATION, _NO_EXPLOIT_LIMITATION]
    limitations.extend(dataset.collection.gaps)
    limitations.extend(dataset.gap_statements())
    if not dataset.collection.complete:
        limitations.append(
            "The import reported errors; the analysed dataset is incomplete."
        )
    return limitations


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result




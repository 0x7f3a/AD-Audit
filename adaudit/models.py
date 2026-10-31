"""Core data model shared by importers, graph, analysis and reporting.

Design notes
------------
*Every* edge is stored as ``source -> target`` with the operational meaning
"whoever controls *source* can leverage this relationship against *target*".
That single convention removes the direction ambiguity that plagues directory
ACL modelling (e.g. a user *has a session on* a computer, but what an auditor
cares about is that compromising the computer exposes the user).

Nothing in this module reaches the network or the filesystem.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


class Severity(str, Enum):
    """Report severity. Independent from :class:`Confidence`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return self.value.upper()

    def downgrade(self, steps: int = 1) -> "Severity":
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        index = min(order.index(self) + steps, len(order) - 1)
        return order[index]

    def upgrade(self, steps: int = 1) -> "Severity":
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        index = max(order.index(self) - steps, 0)
        return order[index]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {value!r}") from exc


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(str, Enum):
    """How strongly the collected evidence supports a statement."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    @property
    def label(self) -> str:
        return self.value.upper()

    @classmethod
    def weakest(cls, values: Iterable["Confidence"]) -> "Confidence":
        values = list(values)
        if not values:
            return cls.POSSIBLE
        return min(values, key=lambda item: item.rank)


_CONFIDENCE_RANK = {
    Confidence.CONFIRMED: 3,
    Confidence.LIKELY: 2,
    Confidence.POSSIBLE: 1,
}


class EvidenceQuality(str, Enum):
    """Provenance quality of a single relationship.

    ``EXPLICIT`` - stated directly in the collected data (a membership list, an
    ACE that grants the right, a logged-on session record).
    ``DERIVED``  - mechanically derived from explicit data (primary group,
    containment from a distinguished name, inherited ACE).
    ``INFERRED`` - a weaker reconstruction that depends on an assumption; such
    edges always reduce the confidence of any path using them.
    """

    EXPLICIT = "explicit"
    DERIVED = "derived"
    INFERRED = "inferred"

    @property
    def confidence(self) -> Confidence:
        return _QUALITY_CONFIDENCE[self]

    @classmethod
    def parse(cls, value: str) -> "EvidenceQuality":
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(f"unknown evidence quality: {value!r}") from exc


_QUALITY_CONFIDENCE = {
    EvidenceQuality.EXPLICIT: Confidence.CONFIRMED,
    EvidenceQuality.DERIVED: Confidence.LIKELY,
    EvidenceQuality.INFERRED: Confidence.POSSIBLE,
}


class ObjectType(str, Enum):
    """Directory object classes AD-Audit understands."""

    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DOMAIN = "domain"
    OU = "ou"
    GPO = "gpo"
    CONTAINER = "container"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: str) -> "ObjectType":
        normalised = str(value or "").strip().lower()
        aliases = {
            "users": cls.USER,
            "groups": cls.GROUP,
            "computers": cls.COMPUTER,
            "domains": cls.DOMAIN,
            "ous": cls.OU,
            "organizationalunit": cls.OU,
            "organizational-unit": cls.OU,
            "gpos": cls.GPO,
            "group-policy-object": cls.GPO,
            "containers": cls.CONTAINER,
        }
        if normalised in aliases:
            return aliases[normalised]
        try:
            return cls(normalised)
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class EvidenceItem:
    """One provenance record supporting an edge."""

    detail: str
    reference: str = ""
    quality: EvidenceQuality = EvidenceQuality.EXPLICIT

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "detail": self.detail,
            "quality": self.quality.value,
        }
        if self.reference:
            payload["reference"] = self.reference
        return payload


@dataclass
class Edge:
    """A typed, directed relationship with provenance."""

    type: str
    source: str
    target: str
    quality: EvidenceQuality = EvidenceQuality.EXPLICIT
    evidence: List[EvidenceItem] = field(default_factory=list)
    inherited: bool = False

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.type, self.source, self.target)

    @property
    def confidence(self) -> Confidence:
        return self.quality.confidence

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence.append(item)
        if item.quality.confidence.rank < self.quality.confidence.rank:
            self.quality = item.quality

    def merge(self, other: "Edge") -> None:
        """Merge duplicate evidence for the same relationship.

        The strongest quality wins: a relationship asserted both by an explicit
        list and by an inherited (derived) ACE is still explicit.
        """
        self.inherited = self.inherited and other.inherited
        for item in other.evidence:
            if item not in self.evidence:
                self.evidence.append(item)
        if other.quality.confidence.rank > self.quality.confidence.rank:
            self.quality = other.quality

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "target": self.target,
            "quality": self.quality.value,
            "inherited": self.inherited,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class DirObject:
    """A normalised directory object (graph node)."""

    id: str
    type: ObjectType
    name: str
    domain: Optional[str] = None
    sid: Optional[str] = None
    dn: Optional[str] = None
    sam: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    provenance: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Human readable ``DOMAIN\\name`` (matches Privesc-Audit's style)."""
        if self.domain and self.domain.lower() not in self.name.lower():
            return f"{self.domain.upper()}\\{self.name}"
        return self.name

    @property
    def is_principal(self) -> bool:
        return self.type in (ObjectType.USER, ObjectType.GROUP, ObjectType.COMPUTER)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
        }
        if self.domain:
            payload["domain"] = self.domain
        if self.sid:
            payload["sid"] = self.sid
        if self.dn:
            payload["dn"] = self.dn
        if self.sam:
            payload["sam"] = self.sam
        if self.attributes:
            payload["attributes"] = _sort_mapping(self.attributes)
        if self.provenance:
            payload["provenance"] = sorted(self.provenance)
        return payload


@dataclass(frozen=True)
class DatasetIssue:
    """A collection/import problem worth surfacing in the report."""

    code: str
    message: str
    level: str = "warning"  # "warning" | "error" | "info"
    reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "code": self.code,
            "level": self.level,
            "message": self.message,
        }
        if self.reference:
            payload["reference"] = self.reference
        return payload


@dataclass
class CollectionInfo:
    """How the analysed dataset came to exist."""

    mode: str = "offline"
    format: str = "unknown"
    inputs: List[str] = field(default_factory=list)
    target_domain: Optional[str] = None
    collected_at: Optional[str] = None
    complete: bool = True
    gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "mode": self.mode,
            "format": self.format,
            "inputs": list(self.inputs),
            "complete": self.complete,
        }
        if self.target_domain:
            payload["target_domain"] = self.target_domain
        if self.collected_at:
            payload["collected_at"] = self.collected_at
        if self.gaps:
            payload["gaps"] = sorted(self.gaps)
        return payload


@dataclass
class DirectoryDataset:
    """Normalised directory data ready for graph construction."""

    objects: Dict[str, DirObject] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    issues: List[DatasetIssue] = field(default_factory=list)
    collection: CollectionInfo = field(default_factory=CollectionInfo)
    stats: Dict[str, int] = field(default_factory=dict)

    def add_object(self, obj: DirObject) -> DirObject:
        return self.objects.setdefault(obj.id, obj)

    def merge_object(self, obj: DirObject) -> DirObject:
        """Insert ``obj`` or merge it into an existing node of the same id."""
        existing = self.objects.get(obj.id)
        if existing is None:
            self.objects[obj.id] = obj
            return obj
        _merge_objects(existing, obj)
        return existing

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def add_issue(self, code: str, message: str, level: str = "warning", reference: str = "") -> None:
        issue = DatasetIssue(code=code, message=message, level=level, reference=reference)
        if issue not in self.issues:
            self.issues.append(issue)

    def object_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for obj in self.objects.values():
            counts[obj.type.value] = counts.get(obj.type.value, 0) + 1
        return dict(sorted(counts.items()))

    def gap_statements(self) -> List[str]:
        """Human readable limitations implied by the collected data."""
        statements: List[str] = []
        counts = self.object_type_counts()
        if counts.get(ObjectType.COMPUTER.value, 0) and not any(
            edge.type in ("AdminTo", "Session") for edge in self.edges
        ):
            statements.append(
                "No local administrator or session data was present; "
                "computer-based exposure is not represented."
            )
        if counts.get(ObjectType.GPO.value, 0) == 0:
            statements.append(
                "No Group Policy Objects were present; GPO-based control paths are not represented."
            )
        if not any(edge.type.startswith(("Generic", "Write", "Owns", "Force")) for edge in self.edges):
            statements.append(
                "No object ACL data was present; permission-based control paths are not represented."
            )
        if counts.get(ObjectType.DOMAIN.value, 0) == 0:
            statements.append("No domain object was present; directory replication rights cannot be analysed.")
        return statements


def _merge_objects(existing: DirObject, incoming: DirObject) -> None:
    """Merge duplicate records for the same object id.

    Explicit distinguishing attributes are preserved; conflicting values are
    recorded as an attribute under ``conflicts`` so the report can show that the
    source data disagreed rather than silently picking one.
    """
    if not existing.sid and incoming.sid:
        existing.sid = incoming.sid
    if not existing.dn and incoming.dn:
        existing.dn = incoming.dn
    if not existing.sam and incoming.sam:
        existing.sam = incoming.sam
    if not existing.domain and incoming.domain:
        existing.domain = incoming.domain
    if incoming.type is not ObjectType.UNKNOWN and existing.type is ObjectType.UNKNOWN:
        existing.type = incoming.type
    for key, value in incoming.attributes.items():
        if key in existing.attributes and existing.attributes[key] != value:
            conflicts = existing.attributes.setdefault("conflicts", {})
            if isinstance(conflicts, dict):
                conflicts.setdefault(key, [existing.attributes[key]])
                if value not in conflicts[key]:
                    conflicts[key].append(value)
            continue
        existing.attributes.setdefault(key, value)
    for ref in incoming.provenance:
        if ref not in existing.provenance:
            existing.provenance.append(ref)


@dataclass(frozen=True)
class PathStep:
    """One hop of a potential privilege path."""

    edge: Edge

    @property
    def type(self) -> str:
        return self.edge.type

    @property
    def source(self) -> str:
        return self.edge.source

    @property
    def target(self) -> str:
        return self.edge.target


@dataclass
class PrivilegePath:
    """An ordered chain of edges from a starting principal to a target."""

    source: str
    target: str
    nodes: Tuple[str, ...]
    steps: Tuple[Edge, ...]

    @property
    def signature(self) -> str:
        return "|".join(f"{edge.type}:{edge.source}->{edge.target}" for edge in self.steps)

    @property
    def chain_key(self) -> Tuple[Any, ...]:
        """Identity of the chain *below* the starting principal.

        Two principals that join the same group share every hop after the first,
        so they produce the same key. Analysis consolidates those into one
        finding instead of printing the same chain once per account.
        """
        first = self.steps[0]
        return (
            self.target,
            first.type,
            first.target,
            tuple((step.type, step.target) for step in self.steps[1:]),
        )

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def confidence(self) -> Confidence:
        return Confidence.weakest(edge.confidence for edge in self.steps)

    def to_dict(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        labels = labels or {}
        return {
            "source": labels.get(self.source, self.source),
            "target": labels.get(self.target, self.target),
            "length": self.length,
            "confidence": self.confidence.value,
            "nodes": [labels.get(node, node) for node in self.nodes],
            "steps": [
                {
                    "from": labels.get(edge.source, edge.source),
                    "to": labels.get(edge.target, edge.target),
                    "relationship": edge.type,
                    "confidence": edge.confidence.value,
                    "evidence": [item.to_dict() for item in edge.evidence],
                }
                for edge in self.steps
            ],
        }


@dataclass
class Finding:
    """A stable, evidence-backed audit result."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    check_id: str
    source_objects: List[str] = field(default_factory=list)
    target_objects: List[str] = field(default_factory=list)
    path: Optional[PrivilegePath] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    impact: str = ""
    recommendation: str = ""
    limitations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    affected_count: int = 1

    @property
    def sort_key(self) -> Tuple[int, int, str, str]:
        return (-self.severity.rank, -self.confidence.rank, self.check_id, self.id)

    def to_dict(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        labels = labels or {}
        payload: Dict[str, Any] = {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "description": self.description,
            "source_objects": [labels.get(obj, obj) for obj in self.source_objects],
            "target_objects": [labels.get(obj, obj) for obj in self.target_objects],
        }
        if self.path is not None:
            payload["path"] = self.path.to_dict(labels)
        else:
            payload["path"] = None
        payload["evidence"] = list(self.evidence)
        payload["impact"] = self.impact
        payload["recommendation"] = self.recommendation
        payload["recommendations"] = list(self.recommendations)
        payload["limitations"] = list(self.limitations)
        payload["prerequisites"] = list(self.prerequisites)
        payload["affected_count"] = self.affected_count
        if self.references:
            payload["references"] = list(self.references)
        return payload


def stable_finding_id(prefix: str, signature: str) -> str:
    """Deterministic finding id derived from the finding's path signature.

    The same dataset and configuration produce the same id on every run, so
    reports can be diffed across assessments.
    """
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def _sort_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    return {key: mapping[key] for key in sorted(mapping)}


def canonical_labels(objects: Dict[str, DirObject]) -> Dict[str, str]:
    """Map object ids to stable display labels for reports."""
    labels: Dict[str, str] = {}
    for obj_id, obj in objects.items():
        labels[obj_id] = obj.label
    return labels

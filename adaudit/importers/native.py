"""AD-Audit's own export format (``schema_version`` 1.0).

This is the format written by the LDAP collector (``--collect
--export-native``). It is a single JSON document::

    {
      "schema_version": "1.0",
      "domain": "corp.example",
      "collected_at": "2026-01-01T00:00:00Z",
      "collection": {"mode": "ldap", "complete": true, "gaps": []},
      "objects": [
        {"id": "S-1-5-21-...-1105", "type": "user", "name": "analyst",
         "domain": "corp.example", "dn": "CN=Analyst,OU=Staff,DC=corp,DC=example",
         "sid": "S-1-5-21-...-1105", "sam": "analyst", "attributes": {}}
      ],
      "relationships": [
        {"type": "MemberOf", "source": "S-1-5-21-...-1105",
         "target": "S-1-5-21-...-512",
         "evidence": [{"detail": "member of Helpdesk", "quality": "explicit",
                       "reference": "ldap:CN=Helpdesk,OU=Groups,DC=corp,DC=example"}]}
      ]
    }

Every relationship type must exist in :mod:`adaudit.relationships`; anything
else is reported and skipped, and edges whose endpoints are missing are
rejected rather than silently dropped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import (
    CollectionInfo,
    DirObject,
    DirectoryDataset,
    Edge,
    EvidenceItem,
    EvidenceQuality,
    ObjectType,
)
from ..normalize import (
    canonical_object_id,
    domain_from_dn,
    normalise_domain,
    normalise_dn,
    normalise_name,
    normalise_sid,
)
from ..relationships import is_known
from .base import DatasetImportError

SCHEMA_VERSION = "1.0"


def load(path: Path, verbose: bool = False) -> DirectoryDataset:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise DatasetImportError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc

    if not isinstance(payload, dict):
        raise DatasetImportError(
            f"{path}: an AD-Audit export must be a JSON object with 'objects' "
            "and 'relationships'"
        )

    objects = payload.get("objects")
    relationships = payload.get("relationships", payload.get("edges", []))
    if not isinstance(objects, list):
        raise DatasetImportError(f"{path}: 'objects' must be a JSON array")
    if not isinstance(relationships, list):
        raise DatasetImportError(f"{path}: 'relationships' must be a JSON array")

    dataset = DirectoryDataset()
    collection_block = payload.get("collection")
    if not isinstance(collection_block, dict):
        collection_block = {}
    dataset.collection = CollectionInfo(
        mode=str(collection_block.get("mode", "offline")),
        format="adaudit",
        inputs=[str(path)],
        target_domain=normalise_domain(payload.get("domain"))
        or normalise_domain(collection_block.get("target_domain")),
        collected_at=_optional_str(payload.get("collected_at")),
        complete=bool(collection_block.get("complete", True)),
        gaps=[str(gap) for gap in _as_list(collection_block.get("gaps"))],
    )

    declared_schema = payload.get("schema_version")
    if declared_schema is None:
        dataset.add_issue(
            "schema-version-missing",
            f"{path}: no schema_version declared; assuming {SCHEMA_VERSION}",
            level="info",
        )
    elif str(declared_schema).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        dataset.add_issue(
            "schema-version-mismatch",
            f"{path}: export schema_version {declared_schema} is not "
            f"compatible with this build (expects {SCHEMA_VERSION}.x); "
            "fields may be missing",
        )

    for index, record in enumerate(objects):
        _add_object(dataset, record, index, str(path))

    for index, record in enumerate(relationships):
        _add_relationship(dataset, record, index, str(path))

    _apply_dn_containment(dataset)
    _dedupe_edges(dataset)
    if any(issue.level == "error" for issue in dataset.issues):
        dataset.collection.complete = False

    dataset.stats["objects"] = len(dataset.objects)
    dataset.stats["relationships"] = len(dataset.edges)
    if not dataset.collection.target_domain:
        dataset.collection.target_domain = _most_common_domain(dataset)
    return dataset


def _add_object(
    dataset: DirectoryDataset,
    record: Any,
    index: int,
    path: str,
) -> None:
    reference = f"{path}#objects[{index}]"
    if not isinstance(record, dict):
        dataset.add_issue(
            "malformed-object",
            f"{reference}: object record is not a JSON object; skipped",
            level="error",
            reference=reference,
        )
        return
    sid = normalise_sid(record.get("sid"))
    dn = normalise_dn(record.get("dn") or record.get("distinguishedname"))
    name = normalise_name(record.get("name") or record.get("sam"))
    domain = normalise_domain(record.get("domain")) or domain_from_dn(dn)
    raw_id = normalise_sid(record.get("id")) or normalise_name(record.get("id"))
    object_id = raw_id or canonical_object_id(sid, dn, domain, name)
    if not object_id:
        dataset.add_issue(
            "object-missing-identifier",
            f"{reference}: object has no id, SID, DN or name; skipped",
            level="error",
            reference=reference,
        )
        return
    if not name:
        dataset.add_issue(
            "object-missing-name",
            f"{reference}: object {object_id} has no name; using its identifier",
            level="info",
            reference=reference,
        )
        name = sid or object_id

    object_type = ObjectType.parse(str(record.get("type", "unknown")))
    if object_type is ObjectType.UNKNOWN:
        dataset.add_issue(
            "object-unknown-type",
            f"{reference}: object {name} has an unrecognised type "
            f"'{record.get('type')}'; it is kept as an unknown object",
            level="info",
            reference=reference,
        )

    attributes = record.get("attributes")
    if not isinstance(attributes, dict):
        attributes = {}

    dataset.merge_object(
        DirObject(
            id=object_id,
            type=object_type,
            name=name,
            domain=domain,
            sid=sid,
            dn=dn,
            sam=normalise_name(record.get("sam")),
            attributes=dict(attributes),
            provenance=[reference],
        )
    )


def _add_relationship(
    dataset: DirectoryDataset,
    record: Any,
    index: int,
    path: str,
) -> None:
    reference = f"{path}#relationships[{index}]"
    if not isinstance(record, dict):
        dataset.add_issue(
            "malformed-relationship",
            f"{reference}: relationship record is not a JSON object; skipped",
            level="error",
            reference=reference,
        )
        return
    edge_type = normalise_name(record.get("type"))
    source = normalise_sid(record.get("source")) or normalise_name(record.get("source"))
    target = normalise_sid(record.get("target")) or normalise_name(record.get("target"))
    if not (edge_type and source and target):
        dataset.add_issue(
            "relationship-missing-fields",
            f"{reference}: relationship needs type, source and target; skipped",
            level="error",
            reference=reference,
        )
        return
    if not is_known(edge_type):
        dataset.add_issue(
            "unknown-relationship",
            f"{reference}: relationship type '{edge_type}' is not supported; skipped",
            level="error",
            reference=reference,
        )
        return
    if source == target:
        dataset.add_issue(
            "self-relationship",
            f"{reference}: relationship {edge_type} points at itself; skipped",
            level="info",
            reference=reference,
        )
        return
    missing = [node for node in (source, target) if node not in dataset.objects]
    if missing:
        dataset.add_issue(
            "relationship-unknown-endpoint",
            f"{reference}: {edge_type} references object(s) not present in the "
            f"export ({', '.join(missing)}); skipped",
            level="error",
            reference=reference,
        )
        return

    evidence_items = _parse_evidence(record.get("evidence"), edge_type, reference)
    quality = evidence_items[0].quality if evidence_items else EvidenceQuality.EXPLICIT
    for item in evidence_items[1:]:
        if item.quality.confidence.rank < quality.confidence.rank:
            quality = item.quality

    dataset.add_edge(
        Edge(
            type=edge_type,
            source=source,
            target=target,
            quality=quality,
            evidence=evidence_items,
            inherited=bool(record.get("inherited", False)),
        )
    )


def _parse_evidence(raw: Any, edge_type: str, reference: str) -> List[EvidenceItem]:
    entries = raw if isinstance(raw, list) else [raw] if raw else []
    items: List[EvidenceItem] = []
    for entry in entries:
        if isinstance(entry, dict):
            detail = normalise_name(entry.get("detail")) or f"{edge_type} relationship in the export"
            item_reference = normalise_name(entry.get("reference")) or reference
            quality_raw = entry.get("quality", EvidenceQuality.EXPLICIT.value)
            try:
                quality = EvidenceQuality.parse(str(quality_raw))
            except ValueError:
                quality = EvidenceQuality.INFERRED
        elif isinstance(entry, str):
            detail = entry
            item_reference = reference
            quality = EvidenceQuality.EXPLICIT
        else:
            continue
        items.append(
            EvidenceItem(detail=detail, reference=item_reference, quality=quality)
        )
    if not items:
        items.append(
            EvidenceItem(
                detail=f"{edge_type} relationship in the export",
                reference=reference,
                quality=EvidenceQuality.EXPLICIT,
            )
        )
    return items


def _apply_dn_containment(dataset: DirectoryDataset) -> None:
    """Add containment edges when the export did not state them.

    A collector normally emits these explicitly; this fallback keeps hand
    written exports consistent and is marked ``derived`` for that reason.
    """
    from ..normalize import dn_key, parent_dn

    by_dn = {dn_key(obj.dn): obj for obj in dataset.objects.values() if obj.dn}
    existing = {(edge.type, edge.source, edge.target) for edge in dataset.edges}
    for obj in list(dataset.objects.values()):
        parent = parent_dn(obj.dn)
        if not parent:
            continue
        container = by_dn.get(dn_key(parent))
        if container is None or container.id == obj.id:
            continue
        if container.type not in (ObjectType.OU, ObjectType.DOMAIN, ObjectType.CONTAINER):
            continue
        if ("Contains", container.id, obj.id) in existing:
            continue
        dataset.add_edge(
            Edge(
                type="Contains",
                source=container.id,
                target=obj.id,
                quality=EvidenceQuality.DERIVED,
                evidence=[
                    EvidenceItem(
                        detail="Containment derived from the object's distinguished name",
                        reference=obj.provenance[0] if obj.provenance else "",
                        quality=EvidenceQuality.DERIVED,
                    )
                ],
            )
        )


def _dedupe_edges(dataset: DirectoryDataset) -> None:
    merged: Dict[tuple, Edge] = {}
    for edge in dataset.edges:
        existing = merged.get(edge.key)
        if existing is None:
            merged[edge.key] = edge
        else:
            existing.merge(edge)
    dataset.edges = [merged[key] for key in sorted(merged)]


def _most_common_domain(dataset: DirectoryDataset) -> Optional[str]:
    counts: Dict[str, int] = {}
    for obj in dataset.objects.values():
        if obj.domain:
            counts[obj.domain] = counts.get(obj.domain, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

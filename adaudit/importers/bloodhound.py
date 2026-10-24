"""BloodHound / SharpHound JSON import.

Supported inputs
----------------
* A ``.zip`` archive as produced by SharpHound or bloodhound-python, containing
  per-class JSON files (``users.json``, ``groups.json``, ``computers.json``,
  ``domains.json``, ``ous.json``, ``gpos.json``, ``containers.json``).
* A directory containing the same files.
* A single JSON document whose top-level keys are those class names and whose
  values are the record arrays (the same records, concatenated).

Field handling is deliberately tolerant about key casing (``Members`` and
``members`` both work) because the export format has drifted between
SharpHound versions. Unknown relationship types are reported, never mapped to
something similar.

Deliberately not modelled from BloodHound data
----------------------------------------------
* Domain trusts (``Trusts``) -- modelled in neither direction, reported as a
  skipped check.
* Kerberoast targets (``SPNTargets``) -- credential attack material, outside
  this tool's scope.
* GPO-derived local group membership (``GPOChanges``) -- requires linking a
  policy's settings back to every affected host; reported as skipped.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    dn_key,
    normalise_domain,
    normalise_dn,
    normalise_guid,
    normalise_name,
    normalise_sid,
    parent_dn,
)
from ..relationships import BLOODHOUND_RIGHT_MAP, is_known
from .base import BLOODHOUND_FILE_KINDS, DatasetImportError

#: local-group arrays on computer records -> (edge type, human description)
_COMPUTER_ACCESS_FIELDS: Tuple[Tuple[str, str, str], ...] = (
    ("LocalAdmins", "AdminTo", "local administrator"),
    ("RemoteDesktopUsers", "CanRDP", "Remote Desktop user"),
    ("PSRemoteUsers", "CanPSRemote", "remote PowerShell user"),
    ("DcomUsers", "ExecuteDCOM", "DCOM user"),
)

#: session arrays on computer records -> session kind shown in evidence
_SESSION_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("Sessions", "interactive"),
    ("PrivilegedSessions", "privileged"),
    ("RegistrySessions", "registry"),
)


def kind_for_filename(filename: str) -> Optional[str]:
    """Return the BloodHound object class for a JSON filename, if it is one."""
    base = Path(filename).name.lower()
    if not base.endswith(".json"):
        return None
    stem = base[:-5]
    for kind in BLOODHOUND_FILE_KINDS:
        if stem == kind or stem.endswith("_" + kind) or stem.endswith("-" + kind):
            return kind
    return None


def load(path: Path, verbose: bool = False) -> DirectoryDataset:
    """Parse a BloodHound export into a normalised dataset."""
    collections, ignored = _read_collections(path)
    if not collections:
        raise DatasetImportError(
            f"{path}: no BloodHound object files found (expected one of: "
            f"{', '.join(BLOODHOUND_FILE_KINDS)}.json)"
        )

    dataset = DirectoryDataset()
    dataset.collection = CollectionInfo(
        mode="offline",
        format="bloodhound",
        inputs=[str(path)],
    )
    for name in sorted(set(ignored)):
        dataset.add_issue(
            "unsupported-export-file",
            f"{path.name}: '{name}' is not a supported object class and was ignored",
            level="info",
            reference=name,
        )

    indexed: List[Tuple[str, str, Dict[str, Any], str]] = []
    # Pass 1: materialise nodes so later passes can resolve references.
    for kind, (records, reference) in collections.items():
        for record in records:
            if not isinstance(record, dict):
                dataset.add_issue(
                    "malformed-record",
                    f"{reference}: record is not a JSON object; skipped",
                    level="error",
                    reference=reference,
                )
                continue
            object_id = _add_object(dataset, kind, record, reference)
            if object_id:
                name = dataset.objects[object_id].name
                indexed.append((kind, f"{reference}#{name}", record, object_id))

    # Pass 2: relationships.
    for kind, reference, record, object_id in indexed:
        _add_record_relationships(dataset, kind, reference, record, object_id)

    _add_structural_edges(dataset)
    _finalise(dataset)
    return dataset


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _read_collections(
    path: Path,
) -> Tuple[Dict[str, Tuple[List[Any], str]], List[str]]:
    if path.is_dir():
        return _read_directory(path)
    if path.suffix.lower() == ".zip":
        return _read_zip(path)
    if path.is_file():
        return _read_single_json(path)
    raise DatasetImportError(f"{path}: not a file or directory")


def _read_directory(
    path: Path,
) -> Tuple[Dict[str, Tuple[List[Any], str]], List[str]]:
    collections: Dict[str, Tuple[List[Any], str]] = {}
    ignored: List[str] = []
    for candidate in sorted(path.iterdir()):
        if not candidate.is_file():
            continue
        kind = kind_for_filename(candidate.name)
        if not kind:
            if candidate.suffix.lower() == ".json":
                ignored.append(candidate.name)
            continue
        records = _load_json_file(candidate)
        collections.setdefault(kind, ([], candidate.name))
        collections[kind][0].extend(records)
    return collections, ignored


def _read_zip(
    path: Path,
) -> Tuple[Dict[str, Tuple[List[Any], str]], List[str]]:
    collections: Dict[str, Tuple[List[Any], str]] = {}
    ignored: List[str] = []
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise DatasetImportError(f"{path}: not a valid ZIP archive ({exc})") from exc
    with archive:
        names = sorted(archive.namelist())
        for name in names:
            if name.endswith("/"):
                continue
            kind = kind_for_filename(name)
            if not kind:
                if name.lower().endswith(".json"):
                    ignored.append(name)
                continue
            try:
                payload = json.loads(archive.read(name).decode("utf-8-sig"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise DatasetImportError(
                    f"{path}: '{name}' is not valid JSON ({exc})"
                ) from exc
            records = _records_from_payload(payload, kind)
            reference = f"{path.name}!{name}"
            collections.setdefault(kind, ([], reference))
            collections[kind][0].extend(records)
    return collections, ignored


def _read_single_json(
    path: Path,
) -> Tuple[Dict[str, Tuple[List[Any], str]], List[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise DatasetImportError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    if not isinstance(payload, dict):
        raise DatasetImportError(
            f"{path}: top-level JSON value is {type(payload).__name__}; "
            "a BloodHound object collection must be an object keyed by class "
            f"({', '.join(BLOODHOUND_FILE_KINDS)})"
        )
    lowered = {str(key).lower(): key for key in payload}
    collections: Dict[str, Tuple[List[Dict[str, Any]], str]] = {}
    for kind in BLOODHOUND_FILE_KINDS:
        if kind in lowered:
            original = lowered[kind]
            collections[kind] = (
                _records_from_payload(payload[original], kind),
                f"{path.name}:{original}",
            )
    ignored = sorted(
        str(key)
        for key, value in payload.items()
        if isinstance(value, list) and str(key).lower() not in BLOODHOUND_FILE_KINDS
    )
    return collections, ignored


def _load_json_file(path: Path) -> List[Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise DatasetImportError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    return _records_from_payload(payload, kind_for_filename(path.name) or "unknown")


def _records_from_payload(payload: Any, kind: str) -> List[Any]:
    if isinstance(payload, list):
        # Non-object entries are kept so the loader can report them.
        return list(payload)
    if isinstance(payload, dict):
        # Some exporters wrap the array in a single key, e.g. {"users": [...]}.
        for key, value in payload.items():
            if str(key).lower() in (kind, "data", "results") and isinstance(value, list):
                return list(value)
        # A single record rather than an array.
        if _pick(payload, "ObjectIdentifier", "objectidentifier", "Properties", "properties"):
            return [payload]
    raise DatasetImportError(
        f"'{kind}.json' has an unexpected structure: expected a JSON array of records"
    )


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------


def _add_object(
    dataset: DirectoryDataset,
    kind: str,
    record: Dict[str, Any],
    reference: str,
) -> Optional[str]:
    props = _pick(record, "Properties", "properties", default={}) or {}
    if not isinstance(props, dict):
        props = {}

    identifier = _pick(
        record, "ObjectIdentifier", "objectidentifier", "ObjectId", "objectid", "sid"
    )
    sid = normalise_sid(
        _pick(props, "objectsid", "objectSid", "ObjectSID", "sid") or identifier
    )
    dn = normalise_dn(_pick(props, "distinguishedname", "distinguishedName", "dn"))
    domain = normalise_domain(_pick(props, "domain", "Domain")) or domain_from_dn(dn)
    raw_name = normalise_name(
        _pick(props, "name", "Name", "samaccountname", "sAMAccountName")
    ) or normalise_name(identifier)

    if kind == "gpos":
        gpo_guid = normalise_guid(identifier) or normalise_guid(dn)
        object_id = gpo_guid
        object_type = ObjectType.GPO
    else:
        object_id = canonical_object_id(sid, dn, domain, raw_name) if (sid or dn or raw_name) else None
        object_type = ObjectType.parse(kind)

    if not object_id:
        dataset.add_issue(
            "record-missing-identifier",
            f"{reference}: a {kind} record has no SID, DN or name; skipped",
            level="error",
            reference=reference,
        )
        return None

    name = _display_name(raw_name, domain, sid, object_id)
    attributes: Dict[str, Any] = {}
    for source_key, target_key in (
        ("highvalue", "highvalue"),
        ("enabled", "enabled"),
        ("admincount", "admincount"),
        ("description", "description"),
        ("operatingsystem", "operatingsystem"),
        ("serviceprincipalnames", "serviceprincipalnames"),
        ("gpcpath", "gpcpath"),
        ("functionallevel", "functionallevel"),
    ):
        value = _pick(props, source_key, source_key.upper())
        if value is not None and value != "":
            attributes[target_key] = value

    if kind != "gpos" and isinstance(_pick(props, "sidhistory", "SIDHistory"), list):
        attributes["sidhistory"] = _pick(props, "sidhistory", "SIDHistory")

    obj = DirObject(
        id=object_id,
        type=object_type,
        name=name,
        domain=domain,
        sid=sid,
        dn=dn,
        sam=_sam_from(name),
        attributes=attributes,
        provenance=[reference],
    )
    dataset.merge_object(obj)
    dataset.stats["objects_read"] = dataset.stats.get("objects_read", 0) + 1
    return object_id


def _display_name(
    raw_name: Optional[str],
    domain: Optional[str],
    sid: Optional[str],
    object_id: str,
) -> str:
    if raw_name:
        if domain and raw_name.lower().endswith("@" + domain):
            return raw_name[: -(len(domain) + 1)]
        if "@" in raw_name:
            return raw_name.split("@", 1)[0]
        return raw_name
    return sid or object_id


def _sam_from(name: str) -> Optional[str]:
    if "\\" in name:
        return name.split("\\", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


def _add_record_relationships(
    dataset: DirectoryDataset,
    kind: str,
    reference: str,
    record: Dict[str, Any],
    object_id: str,
) -> None:
    for ace in _as_list(_pick(record, "Aces", "aces")):
        _add_ace_edge(dataset, ace, object_id, reference)

    if kind == "groups":
        for member in _as_list(_pick(record, "Members", "members")):
            _add_membership_edge(dataset, member, object_id, reference)

    if kind in ("users", "computers"):
        _add_primary_group_edge(dataset, record, object_id, reference)
        _add_delegation_edges(dataset, record, object_id, reference)
        _add_sid_history_edges(dataset, record, object_id, reference)

    if kind == "computers":
        for field, edge_type, description in _COMPUTER_ACCESS_FIELDS:
            for principal in _as_list(_pick(record, field)):
                _add_local_access_edge(
                    dataset, principal, object_id, edge_type, description, reference
                )
        for field, session_kind in _SESSION_FIELDS:
            for session in _as_list(_pick(record, field)):
                _add_session_edge(dataset, session, object_id, session_kind, reference)

    if kind in ("domains", "ous"):
        for link in _as_list(_pick(record, "Links", "links")):
            _add_gpo_link_edge(dataset, link, object_id, reference)

    if kind == "domains":
        trusts = _as_list(_pick(record, "Trusts", "trusts"))
        if trusts:
            dataset.add_issue(
                "trusts-not-modelled",
                f"{reference}: {len(trusts)} domain trust(s) are present but trust "
                "relationships are not modelled; cross-domain paths are not analysed",
                level="info",
                reference=reference,
            )
            dataset.collection.gaps.append(
                "Domain trusts are present but not modelled; only relationships inside "
                "the collected domain were analysed."
            )
        if _as_list(_pick(record, "GPOChanges", "gpchanges", "gpchanges")):
            dataset.add_issue(
                "gpo-changes-not-modelled",
                f"{reference}: GPO-derived local group membership (GPOChanges) is not modelled",
                level="info",
                reference=reference,
            )


def _add_membership_edge(
    dataset: DirectoryDataset,
    member: Any,
    group_id: str,
    reference: str,
) -> None:
    member_id = _reference_id(dataset, member, reference, "member")
    if not member_id or member_id == group_id:
        return
    primary = bool(_pick(member, "PrimaryGroup", "primarygroup", default=False)) if isinstance(member, dict) else False
    detail = (
        "Member of the group by primary-group assignment"
        if primary
        else "Listed as a member of the group"
    )
    _emit_edge(
        dataset,
        "MemberOf",
        member_id,
        group_id,
        EvidenceQuality.EXPLICIT,
        detail,
        reference,
    )


def _add_primary_group_edge(
    dataset: DirectoryDataset,
    record: Dict[str, Any],
    object_id: str,
    reference: str,
) -> None:
    group_sid = normalise_sid(_pick(record, "PrimaryGroupSID", "primarygroupsid"))
    if not group_sid:
        return
    if group_sid != object_id:
        if group_sid not in dataset.objects:
            dataset.add_issue(
                "unresolved-primary-group",
                f"{reference}: primary group {group_sid} is not present in the dataset",
                reference=reference,
            )
            return
        _emit_edge(
            dataset,
            "MemberOf",
            object_id,
            group_sid,
            EvidenceQuality.DERIVED,
            "Primary group assignment (implicit membership)",
            reference,
        )


def _add_delegation_edges(
    dataset: DirectoryDataset,
    record: Dict[str, Any],
    object_id: str,
    reference: str,
) -> None:
    for target in _as_list(_pick(record, "AllowedToDelegate", "allowedtodelegate")):
        target_id = _reference_id(dataset, target, reference, "delegation target")
        if not target_id:
            continue
        _emit_edge(
            dataset,
            "AllowedToDelegate",
            object_id,
            target_id,
            EvidenceQuality.EXPLICIT,
            "Constrained delegation target listed on the account",
            reference,
        )

    if _as_list(_pick(record, "SPNTargets", "spntargets")):
        dataset.add_issue(
            "spn-targets-not-modelled",
            f"{reference}: SPNTargets (Kerberoastable service tickets) are "
            "credential-attack material and are not modelled",
            level="info",
            reference=reference,
        )


def _add_sid_history_edges(
    dataset: DirectoryDataset,
    record: Dict[str, Any],
    object_id: str,
    reference: str,
) -> None:
    for entry in _as_list(_pick(record, "HasSIDHistory", "hassidhistory")):
        history_id = _reference_id(dataset, entry, reference, "SID history entry")
        if not history_id or history_id == object_id:
            continue
        _emit_edge(
            dataset,
            "HasSIDHistory",
            object_id,
            history_id,
            EvidenceQuality.EXPLICIT,
            "SID history entry recorded on the account",
            reference,
        )


def _add_local_access_edge(
    dataset: DirectoryDataset,
    principal: Any,
    computer_id: str,
    edge_type: str,
    description: str,
    reference: str,
) -> None:
    principal_id = _reference_id(dataset, principal, reference, description)
    if not principal_id or principal_id == computer_id:
        return
    _emit_edge(
        dataset,
        edge_type,
        principal_id,
        computer_id,
        EvidenceQuality.EXPLICIT,
        f"Listed in the computer's {description} group",
        reference,
    )


def _add_session_edge(
    dataset: DirectoryDataset,
    session: Any,
    computer_id: str,
    session_kind: str,
    reference: str,
) -> None:
    if not isinstance(session, dict):
        return
    user_sid = normalise_sid(
        _pick(session, "UserSID", "usersid", "ObjectIdentifier", "objectidentifier")
    )
    if not user_sid:
        dataset.add_issue(
            "session-missing-user",
            f"{reference}: a {session_kind} session has no user SID; skipped",
            reference=reference,
        )
        return
    if user_sid not in dataset.objects:
        _placeholder(dataset, user_sid, reference, "session user")
    # Stored as computer -> user: compromising the host exposes the session user.
    _emit_edge(
        dataset,
        "Session",
        computer_id,
        user_sid,
        EvidenceQuality.EXPLICIT,
        f"{session_kind.capitalize()} session of the account on this computer",
        reference,
    )


def _add_gpo_link_edge(
    dataset: DirectoryDataset,
    link: Any,
    container_id: str,
    reference: str,
) -> None:
    if not isinstance(link, dict):
        return
    guid = normalise_guid(_pick(link, "GUID", "guid", "ObjectIdentifier", "objectidentifier"))
    if not guid:
        dataset.add_issue(
            "gpo-link-missing-guid",
            f"{reference}: a GPO link has no GUID; skipped",
            reference=reference,
        )
        return
    gpo_id = guid
    if gpo_id not in dataset.objects:
        dataset.add_issue(
            "gpo-not-collected",
            f"{reference}: GPO {guid} is linked but its object was not collected; "
            "control over that policy cannot be analysed",
            reference=reference,
        )
        return
    enforced = bool(_pick(link, "IsEnforced", "isenforced", "Enforced", default=False))
    detail = "GPO link on the container" + (" (enforced)" if enforced else "")
    _emit_edge(
        dataset,
        "GPOAppliesTo",
        gpo_id,
        container_id,
        EvidenceQuality.EXPLICIT,
        detail,
        reference,
    )


def _add_ace_edge(
    dataset: DirectoryDataset,
    ace: Any,
    target_id: str,
    reference: str,
) -> None:
    if not isinstance(ace, dict):
        return
    principal = normalise_sid(
        _pick(ace, "PrincipalSID", "principalsid", "PrincipalId", "principalid")
    )
    right = _pick(ace, "RightName", "rightname", "Right", "right")
    if not principal:
        dataset.add_issue(
            "ace-missing-principal",
            f"{reference}: an ACE has no principal SID; skipped",
            reference=reference,
        )
        return
    if not right:
        dataset.add_issue(
            "ace-missing-right",
            f"{reference}: an ACE for {principal} has no right name; skipped",
            reference=reference,
        )
        return
    right_name = str(right).strip()
    edge_type = BLOODHOUND_RIGHT_MAP.get(right_name)
    if edge_type is None:
        _note_right(dataset, right_name, reference)
        return
    if principal == target_id:
        return
    if principal not in dataset.objects:
        _placeholder(dataset, principal, reference, "ACE principal")
    inherited = bool(_pick(ace, "IsInherited", "isinherited", default=False))
    detail = f"ACE right '{right_name}' granted on the object" + (
        " (inherited from a parent object)" if inherited else ""
    )
    _emit_edge(
        dataset,
        edge_type,
        principal,
        target_id,
        EvidenceQuality.DERIVED if inherited else EvidenceQuality.EXPLICIT,
        detail,
        reference,
        inherited=inherited,
    )


def _note_right(dataset: DirectoryDataset, right_name: str, reference: str) -> None:
    skipped = dataset.stats.setdefault("_skipped_rights", {})  # type: ignore[assignment]
    if isinstance(skipped, dict):
        skipped[right_name] = skipped.get(right_name, 0) + 1


# ---------------------------------------------------------------------------
# Structural edges
# ---------------------------------------------------------------------------


def _add_structural_edges(dataset: DirectoryDataset) -> None:
    by_dn: Dict[str, DirObject] = {}
    for obj in dataset.objects.values():
        key = dn_key(obj.dn)
        if key and key not in by_dn:
            by_dn[key] = obj

    for obj in list(dataset.objects.values()):
        parent = parent_dn(obj.dn)
        while parent:
            parent_key = dn_key(parent)
            container = by_dn.get(parent_key) if parent_key else None
            if container is not None:
                if container.type in (ObjectType.OU, ObjectType.DOMAIN, ObjectType.CONTAINER):
                    if container.id != obj.id:
                        _emit_edge(
                            dataset,
                            "Contains",
                            container.id,
                            obj.id,
                            EvidenceQuality.DERIVED,
                            "Containment derived from the object's distinguished name",
                            obj.provenance[0] if obj.provenance else "",
                        )
                break
            parent = parent_dn(parent)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _emit_edge(
    dataset: DirectoryDataset,
    edge_type: str,
    source: str,
    target: str,
    quality: EvidenceQuality,
    detail: str,
    reference: str,
    inherited: bool = False,
) -> None:
    if not is_known(edge_type):
        dataset.add_issue(
            "unknown-relationship",
            f"refusing to emit unregistered relationship type '{edge_type}'",
            level="error",
            reference=reference,
        )
        return
    if source == target:
        return
    edge = Edge(
        type=edge_type,
        source=source,
        target=target,
        quality=quality,
        inherited=inherited,
        evidence=[EvidenceItem(detail=detail, reference=reference, quality=quality)],
    )
    dataset.add_edge(edge)


def _reference_id(
    dataset: DirectoryDataset,
    value: Any,
    reference: str,
    role: str,
) -> Optional[str]:
    """Resolve a referenced principal/object, creating a placeholder if needed."""
    if isinstance(value, dict):
        raw = _pick(value, "ObjectIdentifier", "objectidentifier", "PrincipalSID", "sid")
        dn = None
    else:
        raw = value
        dn = None
    sid = normalise_sid(raw)
    object_id = sid
    if not object_id:
        text = normalise_name(raw)
        if text:
            # Some exporters write the DN in ObjectIdentifier for non-SID objects.
            object_id = canonical_object_id(None, normalise_dn(text), None, text)
        elif dn:
            object_id = canonical_object_id(None, normalise_dn(dn), None, None)
    if not object_id:
        dataset.add_issue(
            "unresolved-reference",
            f"{reference}: a {role} reference has no usable identifier; skipped",
            reference=reference,
        )
        return None
    if object_id not in dataset.objects:
        if sid:
            _placeholder(dataset, sid, reference, role)
        else:
            # A DN-addressed object that was never collected cannot be reasoned
            # about; report it instead of inventing a node.
            dataset.add_issue(
                "unresolved-reference",
                f"{reference}: {role} '{object_id}' is not present in the dataset",
                reference=reference,
            )
            return None
    return object_id


def _placeholder(
    dataset: DirectoryDataset,
    sid: str,
    reference: str,
    role: str,
) -> DirObject:
    obj = DirObject(
        id=sid,
        type=ObjectType.UNKNOWN,
        name=sid,
        sid=sid,
        attributes={"unresolved": True, "role": role},
        provenance=[reference],
    )
    dataset.stats["unresolved_objects"] = dataset.stats.get("unresolved_objects", 0) + 1
    dataset.add_issue(
        "unresolved-principal",
        f"{sid} is referenced as a {role} but no directory record was collected; "
        "shown as an unresolved object",
        level="info",
        reference=reference,
    )
    return dataset.merge_object(obj)


def _finalise(dataset: DirectoryDataset) -> None:
    merged: Dict[Tuple[str, str, str], Edge] = {}
    for edge in dataset.edges:
        existing = merged.get(edge.key)
        if existing is None:
            merged[edge.key] = edge
        else:
            existing.merge(edge)
    dataset.edges = [merged[key] for key in sorted(merged)]
    dataset.collection.complete = not any(
        issue.level == "error" for issue in dataset.issues
    )
    skipped = dataset.stats.pop("_skipped_rights", {})
    if isinstance(skipped, dict) and skipped:
        names = ", ".join(f"{name} ({count})" for name, count in sorted(skipped.items()))
        dataset.add_issue(
            "unsupported-rights",
            f"ACE rights that AD-Audit does not model were ignored: {names}",
            level="info",
        )
    unresolved = dataset.stats.get("unresolved_objects", 0)
    if unresolved:
        dataset.collection.gaps.append(
            f"{unresolved} referenced object(s) were not present in the export; "
            "paths through them cannot be evaluated."
        )
    if not dataset.collection.target_domain:
        counts: Dict[str, int] = {}
        for obj in dataset.objects.values():
            if obj.domain:
                counts[obj.domain] = counts.get(obj.domain, 0) + 1
        if counts:
            dataset.collection.target_domain = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    if any(obj.type is ObjectType.DOMAIN for obj in dataset.objects.values()):
        if not any(edge.type == "DCSync" for edge in dataset.edges):
            dataset.collection.gaps.append(
                "No replication rights (DCSync) were present on the domain object; "
                "either none are granted or domain ACLs were not collected."
            )
    dataset.stats["relationships"] = len(dataset.edges)
    dataset.stats["objects"] = len(dataset.objects)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _pick(mapping: Any, *names: str, default: Any = None) -> Any:
    """Case-insensitive lookup across several possible key spellings."""
    if not isinstance(mapping, dict):
        return default
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None:
            return value
    return default

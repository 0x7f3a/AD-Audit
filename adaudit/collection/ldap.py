"""Read-only LDAP collection.

Scope and safety
----------------
* Only :meth:`ldap3.Connection.search` is used. AD-Audit never writes, never
  binds with anything but the supplied account, never resets a password, and
  never touches group membership.
* Collection is deliberately minimal: objects and their security descriptors.
  Session data, GPO settings, trusts and LAPS ciphertext are not collected and
  are reported as gaps.
* Every permission the account lacks turns into a recorded gap instead of a
  silent empty result (``nTSecurityDescriptor`` in particular needs the
  "Read Control" right, which ordinary accounts often lack).

The collector needs the optional ``ldap3`` dependency; the analysis engine does
not. This module is imported lazily by the CLI so offline use never requires it.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

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
    normalise_dn,
    normalise_guid,
    normalise_name,
    normalise_sid,
)
from ..relationships import is_known
from . import sddl

MAX_RANGE_PAGES = 100


class CollectionError(Exception):
    """Raised when live collection cannot proceed."""


@dataclass
class LDAPSettings:
    """Connection settings for a read-only collection."""

    server: str = ""
    base_dn: str = ""
    bind_dn: Optional[str] = None
    password: Optional[str] = None
    ca_cert: Optional[str] = None
    verify_tls: bool = True
    start_tls: bool = False
    timeout: float = 15.0
    page_size: int = 500
    max_entries: int = 50_000

    def __post_init__(self) -> None:
        self.server = (self.server or "").strip()
        self.base_dn = (self.base_dn or "").strip()
        if not self.server:
            raise CollectionError("--server is required for live collection")
        parsed = urlparse(self.server)
        if parsed.scheme not in ("ldap", "ldaps") or not parsed.hostname:
            raise CollectionError(
                f"--server must be an ldap:// or ldaps:// URL with a host, got {self.server!r}"
            )
        if not self.base_dn:
            raise CollectionError("--base-dn is required for live collection")
        if self.page_size < 1:
            raise CollectionError("--page-size must be at least 1")
        if self.timeout <= 0:
            raise CollectionError("--timeout must be greater than zero")


@dataclass
class _Collected:
    objects: Dict[str, DirObject] = field(default_factory=dict)
    dn_index: Dict[str, str] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    issues: List[Tuple[str, str, str]] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    unresolved_members: int = 0
    unmapped_aces: int = 0
    acl_unreadable: int = 0
    errors: int = 0
    # Reference resolved only after every object class has been collected.
    pending_members: List[Tuple[str, str]] = field(default_factory=list)
    pending_primary: List[Tuple[str, str]] = field(default_factory=list)
    pending_sidhistory: List[Tuple[str, str]] = field(default_factory=list)
    pending_delegation: List[Tuple[str, str]] = field(default_factory=list)
    pending_rbcd: List[Tuple[str, str, str]] = field(default_factory=list)


def collect(
    settings: LDAPSettings,
    progress: Optional[Callable[[str], None]] = None,
) -> DirectoryDataset:
    """Collect directory objects read-only and return a normalised dataset."""
    try:
        from ldap3 import Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:  # pragma: no cover - exercised via CLI error path
        raise CollectionError(
            "live collection requires the optional 'ldap3' dependency "
            "(install with: pip install 'ad-audit[ldap]')"
        ) from exc

    notify = progress or (lambda _message: None)

    parsed = urlparse(settings.server)
    use_ssl = parsed.scheme == "ldaps"
    tls = None
    if use_ssl or settings.start_tls:
        tls = Tls(
            validate=ssl.CERT_REQUIRED if settings.verify_tls else ssl.CERT_NONE,
            ca_certs_file=settings.ca_cert or None,
        )

    server = Server(
        parsed.hostname,
        port=parsed.port,
        use_ssl=use_ssl,
        tls=tls,
        connect_timeout=settings.timeout,
        get_info=None,
    )

    collected = _Collected()
    try:
        connection = Connection(
            server,
            user=settings.bind_dn or None,
            password=settings.password or None,
            receive_timeout=settings.timeout,
            auto_bind=False,
            raise_exceptions=False,
        )
        notify(f"connecting to {settings.server}")
        if settings.start_tls and not use_ssl:
            if not connection.open() or not connection.start_tls():
                raise CollectionError(
                    "StartTLS negotiation failed"
                    + (f": {connection.result.get('message')}" if connection.result else "")
                )
            bound = connection.bind()
        else:
            bound = connection.bind()
        if not bound:
            message = (connection.result or {}).get("message", "unknown error")
            description = (connection.result or {}).get("description", "bind failed")
            raise CollectionError(f"LDAP bind failed: {description} ({message})")

        _collect_domain(connection, settings, collected, notify)
        _collect_users(connection, settings, collected, notify)
        _collect_groups(connection, settings, collected, notify)
        _collect_computers(connection, settings, collected, notify)
        _collect_ous(connection, settings, collected, notify)
        _collect_gpos(connection, settings, collected, notify)
        _apply_relationships(connection, settings, collected, notify)
        connection.unbind()
    except CollectionError:
        raise
    except LDAPException as exc:  # pragma: no cover - network dependent
        raise CollectionError(f"LDAP error: {exc}") from exc
    except OSError as exc:  # pragma: no cover - network dependent
        raise CollectionError(f"cannot reach {settings.server}: {exc}") from exc

    return _build_dataset(collected, settings)


# ---------------------------------------------------------------------------
# Searches
# ---------------------------------------------------------------------------


def _search(
    connection: Any,
    base: str,
    search_filter: str,
    attributes: Sequence[str],
    settings: LDAPSettings,
    collected: _Collected,
    label: str,
    scope: Any,
    notify: Callable[[str], None],
) -> List[Dict[str, Any]]:
    notify(f"collecting {label}")
    entries: List[Dict[str, Any]] = []
    try:
        results = connection.extend.standard.paged_search(
            search_base=base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=list(attributes),
            paged_size=settings.page_size,
            generator=True,
            size_limit=settings.max_entries + 1,
        )
        for entry in results:
            if entry.get("type") != "searchResEntry":
                continue
            if len(entries) >= settings.max_entries:
                collected.gaps.append(
                    f"{label}: collection stopped at the {settings.max_entries}-object "
                    "limit; results are incomplete"
                )
                break
            entries.append(entry)
    except Exception as exc:  # ldap3 raises varied types per operation
        collected.errors += 1
        collected.issues.append(
            (
                "collection-error",
                f"{label}: {_short_error(exc)}",
                "warning",
            )
        )
        collected.gaps.append(f"{label} could not be collected completely.")
    return entries


def _short_error(exc: Exception) -> str:
    text = str(exc).strip().replace("\n", " ")
    return text[:300] or exc.__class__.__name__


def _attributes(entry: Dict[str, Any]) -> Dict[str, Any]:
    attrs = entry.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def _single(attrs: Dict[str, Any], name: str) -> Optional[str]:
    value = attrs.get(name)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return None
    return normalise_name(str(value))


def _as_values(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _binary(value: Any) -> Optional[bytes]:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


# ---------------------------------------------------------------------------
# Object collection
# ---------------------------------------------------------------------------


def _collect_domain(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import BASE

    entries = _search(
        connection,
        settings.base_dn,
        "(objectClass=domain)",
        [
            "objectSid",
            "distinguishedName",
            "name",
            "nTSecurityDescriptor",
            "gPLink",
            "ms-DS-MachineAccountQuota",
        ],
        settings,
        collected,
        "domain object",
        BASE,
        notify,
    )
    for entry in entries or [{"attributes": {}, "dn": settings.base_dn}]:
        attrs = _attributes(entry)
        sid = normalise_sid(_single(attrs, "objectSid"))
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "name") or domain_from_dn(dn) or settings.base_dn
        object_id = canonical_object_id(sid, dn, domain_from_dn(dn), name)
        if not object_id:
            collected.issues.append(
                ("domain-missing-identifier", "domain object has no SID or DN", "error")
            )
            continue
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.DOMAIN,
                name=name,
                domain=domain_from_dn(dn),
                sid=sid,
                dn=dn,
                attributes={
                    "gplink": _single(attrs, "gPLink"),
                    "machineaccountquota": _single(attrs, "ms-DS-MachineAccountQuota"),
                },
                provenance=[f"ldap:{dn or settings.base_dn}"],
            ),
        )
        _add_security_descriptor_edges(
            collected, object_id, "domain", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


def _collect_users(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import SUBTREE

    entries = _search(
        connection,
        settings.base_dn,
        "(&(objectCategory=person)(objectClass=user))",
        [
            "objectSid",
            "distinguishedName",
            "sAMAccountName",
            "name",
            "primaryGroupID",
            "userAccountControl",
            "nTSecurityDescriptor",
            "msDS-AllowedToDelegateTo",
            "sIDHistory",
            "servicePrincipalName",
        ],
        settings,
        collected,
        "users",
        SUBTREE,
        notify,
    )
    for entry in entries:
        attrs = _attributes(entry)
        sid = normalise_sid(_single(attrs, "objectSid"))
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "sAMAccountName") or _single(attrs, "name") or sid
        if not sid:
            collected.issues.append(
                ("object-missing-sid", f"user {dn or name} has no readable objectSid", "warning")
            )
        object_id = canonical_object_id(sid, dn, settings_domain(settings), name)
        if not object_id:
            continue
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.USER,
                name=name or object_id,
                domain=settings_domain(settings),
                sid=sid,
                dn=dn,
                sam=name,
                attributes={
                    "primarygroupid": _single(attrs, "primaryGroupID"),
                    "useraccountcontrol": _single(attrs, "userAccountControl"),
                },
                provenance=[f"ldap:{dn or name}"],
            ),
        )
        object_id = collected.dn_index.get(dn_key(dn) or "", object_id)
        _queue_primary_group(collected, object_id, attrs)
        _queue_sid_history(collected, object_id, attrs)
        _queue_delegation(collected, object_id, attrs)
        _add_security_descriptor_edges(
            collected, object_id, "user", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


def _collect_groups(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import SUBTREE

    entries = _search(
        connection,
        settings.base_dn,
        "(objectClass=group)",
        [
            "objectSid",
            "distinguishedName",
            "sAMAccountName",
            "name",
            "member",
            "nTSecurityDescriptor",
            "groupType",
        ],
        settings,
        collected,
        "groups",
        SUBTREE,
        notify,
    )
    for entry in entries:
        attrs = _attributes(entry)
        sid = normalise_sid(_single(attrs, "objectSid"))
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "sAMAccountName") or _single(attrs, "name") or sid
        object_id = canonical_object_id(sid, dn, settings_domain(settings), name)
        if not object_id:
            continue
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.GROUP,
                name=name or object_id,
                domain=settings_domain(settings),
                sid=sid,
                dn=dn,
                sam=name,
                attributes={"grouptype": _single(attrs, "groupType")},
                provenance=[f"ldap:{dn or name}"],
            ),
        )
        object_id = collected.dn_index.get(dn_key(dn) or "", object_id)
        members = _read_members(connection, entry, attrs, settings, collected)
        for member_dn in members:
            collected.pending_members.append((object_id, member_dn))
        _add_security_descriptor_edges(
            collected, object_id, "group", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


def _collect_computers(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import SUBTREE

    entries = _search(
        connection,
        settings.base_dn,
        "(objectClass=computer)",
        [
            "objectSid",
            "distinguishedName",
            "sAMAccountName",
            "name",
            "operatingSystem",
            "primaryGroupID",
            "nTSecurityDescriptor",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ],
        settings,
        collected,
        "computers",
        SUBTREE,
        notify,
    )
    for entry in entries:
        attrs = _attributes(entry)
        sid = normalise_sid(_single(attrs, "objectSid"))
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "sAMAccountName") or _single(attrs, "name") or sid
        object_id = canonical_object_id(sid, dn, settings_domain(settings), name)
        if not object_id:
            continue
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.COMPUTER,
                name=name or object_id,
                domain=settings_domain(settings),
                sid=sid,
                dn=dn,
                sam=name,
                attributes={"operatingsystem": _single(attrs, "operatingSystem")},
                provenance=[f"ldap:{dn or name}"],
            ),
        )
        object_id = collected.dn_index.get(dn_key(dn) or "", object_id)
        _queue_primary_group(collected, object_id, attrs)
        _queue_delegation(collected, object_id, attrs)
        rbcd = _binary(attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))
        if rbcd:
            for principal in sddl.describe_allowed_to_act(rbcd):
                collected.pending_rbcd.append(
                    (principal, object_id, f"ldap:{dn_key(dn or '')}")
                )
        _add_security_descriptor_edges(
            collected, object_id, "computer", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


def _collect_ous(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import SUBTREE

    entries = _search(
        connection,
        settings.base_dn,
        "(objectClass=organizationalUnit)",
        ["distinguishedName", "name", "nTSecurityDescriptor", "gPLink"],
        settings,
        collected,
        "organizational units",
        SUBTREE,
        notify,
    )
    for entry in entries:
        attrs = _attributes(entry)
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "name") or dn
        object_id = canonical_object_id(None, dn, None, name)
        if not object_id:
            continue
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.OU,
                name=name or object_id,
                dn=dn,
                attributes={"gplink": _single(attrs, "gPLink")},
                provenance=[f"ldap:{dn or name}"],
            ),
        )
        object_id = collected.dn_index.get(dn_key(dn) or "", object_id)
        _add_security_descriptor_edges(
            collected, object_id, "ou", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


def _collect_gpos(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    from ldap3 import SUBTREE

    entries = _search(
        connection,
        settings.base_dn,
        "(objectClass=groupPolicyContainer)",
        ["distinguishedName", "displayName", "name", "nTSecurityDescriptor", "gPCFileSysPath"],
        settings,
        collected,
        "group policy objects",
        SUBTREE,
        notify,
    )
    for entry in entries:
        attrs = _attributes(entry)
        dn = normalise_dn(_single(attrs, "distinguishedName")) or normalise_dn(entry.get("dn"))
        name = _single(attrs, "displayName") or _single(attrs, "name") or dn
        object_id = canonical_object_id(None, dn, None, name)
        if not object_id:
            continue
        guid = normalise_guid(_single(attrs, "name"))
        _store(
            collected,
            DirObject(
                id=object_id,
                type=ObjectType.GPO,
                name=name or object_id,
                dn=dn,
                attributes={
                    "guid": guid,
                    "gpcpath": _single(attrs, "gPCFileSysPath"),
                },
                provenance=[f"ldap:{dn or name}"],
            ),
        )
        object_id = collected.dn_index.get(dn_key(dn) or "", object_id)
        _add_security_descriptor_edges(
            collected, object_id, "gpo", _binary(attrs.get("nTSecurityDescriptor")), dn
        )


# ---------------------------------------------------------------------------
# Relationship helpers
# ---------------------------------------------------------------------------


def _store(collected: _Collected, obj: DirObject) -> None:
    existing = collected.objects.get(obj.id)
    if existing is None:
        collected.objects[obj.id] = obj
    else:
        for key, value in obj.attributes.items():
            existing.attributes.setdefault(key, value)
        for reference in obj.provenance:
            if reference not in existing.provenance:
                existing.provenance.append(reference)
    if obj.dn:
        collected.dn_index.setdefault(dn_key(obj.dn) or "", obj.id)


def _edge(
    collected: _Collected,
    edge_type: str,
    source: str,
    target: str,
    quality: EvidenceQuality,
    detail: str,
    reference: str,
    inherited: bool = False,
) -> None:
    if not is_known(edge_type):
        collected.issues.append(
            ("unknown-relationship", f"refusing to emit '{edge_type}'", "error")
        )
        return
    if source == target:
        return
    collected.edges.append(
        Edge(
            type=edge_type,
            source=source,
            target=target,
            quality=quality,
            inherited=inherited,
            evidence=[EvidenceItem(detail=detail, reference=reference, quality=quality)],
        )
    )


def _queue_primary_group(
    collected: _Collected,
    object_id: str,
    attrs: Dict[str, Any],
) -> None:
    rid = _single(attrs, "primaryGroupID")
    if rid and rid.isdigit():
        collected.pending_primary.append((object_id, rid))


def _queue_sid_history(
    collected: _Collected,
    object_id: str,
    attrs: Dict[str, Any],
) -> None:
    for raw in _as_values(attrs.get("sIDHistory")):
        sid = normalise_sid(raw)
        if sid and sid != object_id:
            collected.pending_sidhistory.append((object_id, sid))


def _queue_delegation(
    collected: _Collected,
    object_id: str,
    attrs: Dict[str, Any],
) -> None:
    for value in _as_values(attrs.get("msDS-AllowedToDelegateTo")):
        if value:
            collected.pending_delegation.append((object_id, str(value)))


def _resolve_pending(collected: _Collected) -> None:
    """Resolve references that may point at objects collected later."""
    domain_sid = _domain_sid(collected)
    for object_id, rid in collected.pending_primary:
        if not domain_sid:
            collected.issues.append(
                (
                    "primary-group-unresolved",
                    "domain SID unavailable; primary group memberships were not added",
                    "warning",
                )
            )
            break
        group_sid = f"{domain_sid}-{rid}"
        if group_sid not in collected.objects:
            collected.issues.append(
                (
                    "primary-group-missing",
                    f"primary group {group_sid} was not collected",
                    "info",
                )
            )
            continue
        _edge(
            collected,
            "MemberOf",
            object_id,
            group_sid,
            EvidenceQuality.DERIVED,
            f"Primary group assignment (primaryGroupID {rid})",
            "ldap:primaryGroupID",
        )

    for group_id, member_dn in collected.pending_members:
        member_id = collected.dn_index.get(dn_key(member_dn) or "")
        if not member_id:
            collected.unresolved_members += 1
            continue
        _edge(
            collected,
            "MemberOf",
            member_id,
            group_id,
            EvidenceQuality.EXPLICIT,
            "Listed in the group's member attribute",
            "ldap:member",
        )

    for object_id, sid in collected.pending_sidhistory:
        if sid not in collected.objects:
            collected.issues.append(
                ("sidhistory-uncollected", f"SID history {sid} has no collected object", "info")
            )
            continue
        _edge(
            collected,
            "HasSIDHistory",
            object_id,
            sid,
            EvidenceQuality.EXPLICIT,
            "SID history entry recorded on the account",
            "ldap:sIDHistory",
        )

    hosts = _computer_host_index(collected)
    for object_id, spn in collected.pending_delegation:
        host = spn.split("/", 1)[1] if "/" in spn else spn
        short = host.split(".", 1)[0].rstrip("$").lower()
        match = hosts.get(short)
        if not match:
            collected.issues.append(
                (
                    "delegation-target-unresolved",
                    f"delegation target {spn} matches no collected computer",
                    "info",
                )
            )
            continue
        _edge(
            collected,
            "AllowedToDelegate",
            object_id,
            match,
            EvidenceQuality.EXPLICIT,
            f"Constrained delegation to {spn}",
            "ldap:msDS-AllowedToDelegateTo",
        )

    for principal, computer_id, reference in collected.pending_rbcd:
        _edge(
            collected,
            "AllowedToAct",
            principal,
            computer_id,
            EvidenceQuality.EXPLICIT,
            "Principal listed in msDS-AllowedToActOnBehalfOfOtherIdentity",
            reference,
        )


def _computer_host_index(collected: _Collected) -> Dict[str, str]:
    index: Dict[str, str] = {}
    for obj in collected.objects.values():
        if obj.type is not ObjectType.COMPUTER:
            continue
        for candidate in {obj.name, obj.sam or "", (obj.sam or "").rstrip("$")}:
            if candidate:
                index.setdefault(candidate.lower().rstrip("$"), obj.id)
        if obj.dn:
            first = obj.dn.split(",", 1)[0]
            if "=" in first:
                index.setdefault(first.split("=", 1)[1].lower(), obj.id)
    return index


def _add_security_descriptor_edges(
    collected: _Collected,
    object_id: str,
    target_type: str,
    descriptor: Optional[bytes],
    dn: Optional[str],
) -> None:
    if not descriptor:
        # Aggregated: a least-privilege account may lack Read Control on most
        # objects, which would otherwise flood the report with one issue each.
        collected.acl_unreadable += 1
        return
    reference = f"ldap:{dn_key(dn or '')}"
    owner = sddl.parse_owner(descriptor)
    if owner and owner != object_id:
        _edge(
            collected,
            "Owns",
            owner,
            object_id,
            EvidenceQuality.EXPLICIT,
            "Owner recorded in the object's security descriptor",
            reference,
        )
    try:
        grants = sddl.parse_security_descriptor(descriptor)
    except sddl.SecurityDescriptorError as exc:
        collected.issues.append(
            (
                "acl-parse-error",
                f"security descriptor for {dn or object_id} could not be parsed: {exc}",
                "warning",
            )
        )
        return
    for grant in grants:
        relationship = sddl.map_grant(grant, target_type)
        if relationship is None:
            collected.unmapped_aces += 1
            continue
        if grant.sid == object_id:
            continue
        _edge(
            collected,
            relationship,
            grant.sid,
            object_id,
            EvidenceQuality.DERIVED if grant.inherited else EvidenceQuality.EXPLICIT,
            sddl.describe_grant(grant, relationship),
            reference,
            inherited=grant.inherited,
        )


def _read_members(
    connection: Any,
    entry: Dict[str, Any],
    attrs: Dict[str, Any],
    settings: LDAPSettings,
    collected: _Collected,
) -> List[str]:
    """Read a group's members, following ranged attributes when present."""
    for key, value in attrs.items():
        if key.lower().startswith("member;range"):
            dn = _single(attrs, "distinguishedName") or entry.get("dn")
            return _read_ranged_members(connection, dn, collected)
    return [str(value) for value in _as_values(attrs.get("member")) if value]


def _read_ranged_members(
    connection: Any,
    group_dn: Optional[str],
    collected: _Collected,
) -> List[str]:
    from ldap3 import BASE

    if not group_dn:
        return []
    members: List[str] = []
    start = 0
    for _ in range(MAX_RANGE_PAGES):
        try:
            ok = connection.search(
                group_dn,
                "(objectClass=*)",
                search_scope=BASE,
                attributes=[f"member;range={start}-*"],
                size_limit=0,
            )
        except Exception as exc:  # pragma: no cover - network dependent
            collected.issues.append(
                ("member-range-error", f"ranged member read failed: {_short_error(exc)}", "warning")
            )
            break
        if not ok or not connection.response:
            break
        attributes = connection.response[0].get("attributes", {})
        key = next((name for name in attributes if str(name).lower().startswith("member")), None)
        if key is None:
            break
        values = _as_values(attributes[key])
        members.extend(str(value) for value in values if value)
        if ";" not in str(key):
            break
        range_spec = str(key).split(";", 1)[1]
        if range_spec.lower().endswith("-*"):
            break
        try:
            start = int(range_spec.rsplit("-", 1)[1]) + 1
        except (IndexError, ValueError):
            break
    else:
        collected.gaps.append("group member enumeration hit the range-page limit; membership may be incomplete")
    return members


def _domain_sid(collected: _Collected) -> Optional[str]:
    for obj in collected.objects.values():
        if obj.type is ObjectType.DOMAIN and obj.sid:
            return obj.sid
    return None


def settings_domain(settings: LDAPSettings) -> Optional[str]:
    return domain_from_dn(settings.base_dn)


def _parse_gplink(value: Optional[str]) -> List[Tuple[str, bool]]:
    """Parse ``gPLink`` into (GPO DN, enabled) pairs."""
    if not value:
        return []
    links: List[Tuple[str, bool]] = []
    for raw in value.split("]["):
        token = raw.strip("[]")
        if not token:
            continue
        parts = token.split(";")
        target = parts[0]
        options = parts[1] if len(parts) > 1 else "0"
        if not target.lower().startswith("ldap://"):
            continue
        dn = target[7:]
        enabled = not (options.isdigit() and int(options) & 1)
        links.append((normalise_dn(dn) or dn, enabled))
    return links


def _apply_relationships(
    connection: Any,
    settings: LDAPSettings,
    collected: _Collected,
    notify: Callable[[str], None],
) -> None:
    notify("resolving relationships")
    _resolve_pending(collected)
    by_dn = {dn_key(obj.dn): obj for obj in collected.objects.values() if obj.dn}
    for obj in list(collected.objects.values()):
        if obj.type not in (ObjectType.DOMAIN, ObjectType.OU):
            continue
        for gpo_dn, enabled in _parse_gplink(obj.attributes.get("gplink")):
            gpo = by_dn.get(dn_key(gpo_dn))
            if gpo is None or gpo.type is not ObjectType.GPO:
                collected.issues.append(
                    (
                        "gpo-link-unresolved",
                        f"{obj.dn} links a policy that was not collected ({gpo_dn})",
                        "info",
                    )
                )
                continue
            if not enabled:
                continue
            _edge(
                collected,
                "GPOAppliesTo",
                gpo.id,
                obj.id,
                EvidenceQuality.EXPLICIT,
                "Policy linked on the container (gPLink)",
                f"ldap:{dn_key(obj.dn or '')}",
            )

    # Containment from DN structure, using only collected parents.
    for obj in list(collected.objects.values()):
        parent = obj.dn
        while parent:
            parent = parent.split(",", 1)[1] if "," in parent else ""
            if not parent:
                break
            container = by_dn.get(dn_key(parent))
            if container is None:
                continue
            if container.type in (ObjectType.OU, ObjectType.DOMAIN, ObjectType.CONTAINER):
                _edge(
                    collected,
                    "Contains",
                    container.id,
                    obj.id,
                    EvidenceQuality.DERIVED,
                    "Containment derived from the object's distinguished name",
                    f"ldap:{dn_key(obj.dn or '')}",
                )
            break


def _build_dataset(collected: _Collected, settings: LDAPSettings) -> DirectoryDataset:
    _materialise_missing_endpoints(collected)
    dataset = DirectoryDataset()
    dataset.objects = dict(collected.objects)
    edges: Dict[Tuple[str, str, str], Edge] = {}
    for edge in collected.edges:
        existing = edges.get(edge.key)
        if existing is None:
            edges[edge.key] = edge
        else:
            existing.merge(edge)
    dataset.edges = [edges[key] for key in sorted(edges)]
    domain = settings_domain(settings)
    gaps = list(collected.gaps)
    gaps.append(
        "Sessions and logged-on users are not collected over LDAP; "
        "session-exposure paths are not represented."
    )
    gaps.append(
        "Group Policy settings are not parsed; only policy links and their ACLs are analysed."
    )
    if collected.unresolved_members:
        gaps.append(
            f"{collected.unresolved_members} group member reference(s) pointed at objects "
            "outside the collected scope."
        )
    if collected.unmapped_aces:
        gaps.append(
            f"{collected.unmapped_aces} DACL entries did not map to a modelled relationship "
            "(read-only rights, denies, or unmodelled writes)."
        )
    if collected.acl_unreadable:
        gaps.append(
            f"{collected.acl_unreadable} object(s) had no readable security descriptor; "
            "permission-based paths through them are unknown."
        )
        dataset_issue = (
            "acl-not-readable",
            f"{collected.acl_unreadable} object(s) returned no readable security "
            "descriptor (Read Control is required); ACL analysis is incomplete",
            "warning",
        )
    else:
        dataset_issue = None
    dataset.collection = CollectionInfo(
        mode="ldap",
        format="adaudit",
        inputs=[settings.server],
        target_domain=domain,
        collected_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        complete=collected.errors == 0,
        gaps=gaps,
    )
    for code, message, level in collected.issues:
        dataset.add_issue(code, message, level=level)
    if dataset_issue is not None:
        dataset.add_issue(*dataset_issue)
    dataset.stats["objects"] = len(dataset.objects)
    dataset.stats["relationships"] = len(dataset.edges)
    return dataset


def _materialise_missing_endpoints(collected: _Collected) -> None:
    """Keep edges whose principal SID was never collected as unresolved nodes.

    An ACE naming a SID is still real evidence; dropping it silently would hide
    a grant. The node is explicitly marked unresolved so findings that rely on
    it are downgraded and the report says so.
    """
    known = set(collected.objects)
    created = 0
    for edge in collected.edges:
        for node in (edge.source, edge.target):
            if node in known:
                continue
            collected.objects[node] = DirObject(
                id=node,
                type=ObjectType.UNKNOWN,
                name=node,
                sid=normalise_sid(node),
                attributes={"unresolved": True},
                provenance=["ldap:security-descriptor"],
            )
            known.add(node)
            created += 1
    if created:
        collected.issues.append(
            (
                "unresolved-principal",
                f"{created} SID(s) appear in security descriptors but were not "
                "collected as directory objects; they are shown as unresolved",
                "info",
            )
        )

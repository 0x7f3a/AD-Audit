"""Catalogue of relationship types, their meaning and their prerequisites.

Every supported edge type has exactly one documented meaning. Importers must
map source data onto these names or report that they could not; they must never
emit an unknown or guessed relationship. Keeping the catalogue in one place is
what makes path explanations (and the JSON schema) stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple


@dataclass(frozen=True)
class EdgeSpec:
    """Static description of a typed relationship."""

    name: str
    category: str
    explanation: str
    prerequisites: str = ""
    weight: int = 2  # 1..3: rough impact of the relationship itself
    remediation: str = ""


_REMEDIATION = {
    "membership": (
        "Review the membership, remove accounts that do not need the role, and "
        "prefer time-bound, auditable role assignment over standing membership."
    ),
    "permission": (
        "Review the ACE on the target object, remove unnecessary modification "
        "rights, and confirm the delegation is required and documented."
    ),
    "delegation": (
        "Review the delegation configuration, restrict it to the intended "
        "services, and remove principals that no longer need it."
    ),
    "remote-access": (
        "Review the remote access rights on the target host and restrict them "
        "to the accounts that genuinely administer it."
    ),
    "session-exposure": (
        "Reduce where privileged or shared accounts are used interactively, "
        "and treat the affected host as a credential-exposure point."
    ),
    "containment": (
        "Review who can modify the container and whether inherited rights or "
        "GPO links grant unexpected control over its contents."
    ),
    "gpo": (
        "Review who can edit or link the policy and restrict change rights to "
        "the group policy administrators."
    ),
    "replication": (
        "Restrict directory replication rights to domain controllers only and "
        "review the holders of DS-Replication-Get-Changes-All."
    ),
    "sid-history": (
        "Review the SID history entries on the account and remove stale SIDs "
        "that grant unintended access."
    ),
}


def _spec(
    name: str,
    category: str,
    explanation: str,
    prerequisites: str = "",
    weight: int = 2,
) -> EdgeSpec:
    return EdgeSpec(
        name=name,
        category=category,
        explanation=explanation,
        prerequisites=prerequisites,
        weight=weight,
        remediation=_REMEDIATION.get(category, ""),
    )


_SPECS: Tuple[EdgeSpec, ...] = (
    # ---- membership -------------------------------------------------------
    _spec(
        "MemberOf",
        "membership",
        "{source} is a member of {target}; group membership is transitive and "
        "confers every right the group holds.",
        prerequisites="The account is enabled and can authenticate.",
        weight=2,
    ),
    _spec(
        "HasSIDHistory",
        "sid-history",
        "{source} carries the SID of {target} in its SID history, so access "
        "granted to {target} may apply to {source}.",
        prerequisites="The account authenticates and the target SID is still "
        "granted access by the resource.",
        weight=3,
    ),
    # ---- object permissions ----------------------------------------------
    _spec(
        "GenericAll",
        "permission",
        "{source} holds full control over {target} and can grant itself any "
        "further right on the object.",
        prerequisites="Object permissions apply as granted; no extra privilege "
        "is required.",
        weight=3,
    ),
    _spec(
        "GenericWrite",
        "permission",
        "{source} can write attributes of {target}, for example add itself to a "
        "group or set a script path.",
        prerequisites="The targeted attribute is not protected by additional "
        "validation.",
        weight=2,
    ),
    _spec(
        "WriteDacl",
        "permission",
        "{source} can rewrite the permissions of {target} and grant itself full "
        "control.",
        weight=3,
    ),
    _spec(
        "WriteOwner",
        "permission",
        "{source} can take ownership of {target} and then change its permissions.",
        weight=3,
    ),
    _spec(
        "Owns",
        "permission",
        "{source} owns {target} and can take control by rewriting its permissions.",
        weight=3,
    ),
    _spec(
        "AllExtendedRights",
        "permission",
        "{source} holds all extended rights on {target}, which includes "
        "operations such as password reset and directory replication.",
        weight=3,
    ),
    _spec(
        "ForceChangePassword",
        "permission",
        "{source} can reset the password of {target} without knowing the "
        "current one.",
        weight=3,
    ),
    _spec(
        "AddMember",
        "permission",
        "{source} can add arbitrary principals to {target}.",
        weight=3,
    ),
    _spec(
        "AddSelf",
        "permission",
        "{source} can add itself to {target}.",
        weight=3,
    ),
    _spec(
        "DCSync",
        "replication",
        "{source} holds directory replication rights over {target} and is "
        "permitted to request credential material from it.",
        prerequisites="Replication rights are effective on the domain object.",
        weight=3,
    ),
    _spec(
        "ReadLAPSPassword",
        "permission",
        "{source} can read the LAPS-managed local administrator password of "
        "{target}.",
        weight=2,
    ),
    _spec(
        "ReadGMSAPassword",
        "permission",
        "{source} can read the password of the group managed service account "
        "{target}.",
        weight=2,
    ),
    # ---- delegation -------------------------------------------------------
    _spec(
        "AllowedToAct",
        "delegation",
        "{source} may impersonate other users to {target} through "
        "resource-based constrained delegation.",
        prerequisites="A service on {target} is reachable and the delegation "
        "configuration is active.",
        weight=3,
    ),
    _spec(
        "AllowedToDelegate",
        "delegation",
        "{source} holds constrained delegation to {target}.",
        prerequisites="A service ticket for {target} can be obtained from "
        "{source}.",
        weight=2,
    ),
    # ---- remote access ----------------------------------------------------
    _spec(
        "AdminTo",
        "remote-access",
        "{source} has local administrator rights on {target}.",
        prerequisites="The host is reachable and the account can authenticate "
        "to it.",
        weight=3,
    ),
    _spec(
        "CanRDP",
        "remote-access",
        "{source} may log on to {target} over Remote Desktop.",
        weight=1,
    ),
    _spec(
        "CanPSRemote",
        "remote-access",
        "{source} may run remote PowerShell commands on {target}.",
        weight=2,
    ),
    _spec(
        "ExecuteDCOM",
        "remote-access",
        "{source} may invoke code on {target} through DCOM.",
        weight=2,
    ),
    # ---- sessions ---------------------------------------------------------
    _spec(
        "Session",
        "session-exposure",
        "{target} has a session on {source}; compromise of the host can expose "
        "the logged-on account's credentials.",
        prerequisites="The session is still active or its credential material "
        "remains recoverable on the host.",
        weight=2,
    ),
    # ---- structure --------------------------------------------------------
    _spec(
        "Contains",
        "containment",
        "{source} is the container of {target}; control of the container can "
        "influence the objects inside it, for example by linking a policy.",
        prerequisites="Control of the container includes rights to modify its "
        "policy links or move objects.",
        weight=1,
    ),
    _spec(
        "GPOAppliesTo",
        "gpo",
        "{source} is linked to {target}, so control of the policy affects every "
        "object it applies to.",
        prerequisites="The policy link is enabled and not blocked by inheritance.",
        weight=2,
    ),
)

EDGE_SPECS: Dict[str, EdgeSpec] = {spec.name: spec for spec in _SPECS}

#: Relationship types that grant direct control over the target object.
CONTROL_RELATIONSHIPS = frozenset(
    {
        "GenericAll",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        "ForceChangePassword",
        "AddMember",
        "AddSelf",
        "DCSync",
        "AllowedToAct",
        "HasSIDHistory",
    }
)

#: Canonical traversal order used to make path search deterministic.
RELATIONSHIP_ORDER: Dict[str, int] = {
    spec.name: index for index, spec in enumerate(_SPECS)
}

#: Names used by BloodHound exports, mapped to AD-Audit relationship types.
#: Anything absent here is *reported* as unsupported, never silently dropped.
BLOODHOUND_RIGHT_MAP: Dict[str, str] = {
    "MemberOf": "MemberOf",
    "AdminTo": "AdminTo",
    "CanRDP": "CanRDP",
    "CanPSRemote": "CanPSRemote",
    "ExecuteDCOM": "ExecuteDCOM",
    "Owns": "Owns",
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "ForceChangePassword": "ForceChangePassword",
    "AddMember": "AddMember",
    "AddSelf": "AddSelf",
    "AllExtendedRights": "AllExtendedRights",
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "DCSync": "DCSync",
    "AllowedToAct": "AllowedToAct",
    "AllowedToDelegate": "AllowedToDelegate",
    "HasSIDHistory": "HasSIDHistory",
    "GpLink": "GPOAppliesTo",
    "GPLink": "GPOAppliesTo",
}

#: BloodHound rights recognised but intentionally not modelled yet. They are
#: reported as skipped checks so an empty result is never mistaken for a clean
#: result.
UNMODELLED_BLOODHOUND_RIGHTS = frozenset(
    {
        "AddKeyCredentialLink",
        "WriteSPN",
        "WriteAccountRestrictions",
        "SyncLAPSPassword",
        "DumpSMSAPassword",
        "SQLAdmin",
        "TrustedBy",
        "SameForestTrust",
        "CrossForestTrust",
        "SPNTarget",
        "WriteGPLink",
        "ReadLAPSPassword",
    }
) - set(BLOODHOUND_RIGHT_MAP)


def edge_spec(name: str) -> Optional[EdgeSpec]:
    return EDGE_SPECS.get(name)


def explain_edge(edge_type: str, source_label: str, target_label: str) -> str:
    """One sentence explaining why an edge matters in a path."""
    spec = EDGE_SPECS.get(edge_type)
    if spec is None:
        return f"{source_label} has an unrecognised relationship ({edge_type}) to {target_label}."
    return spec.explanation.format(source=source_label, target=target_label)


def edge_category(edge_type: str) -> str:
    spec = EDGE_SPECS.get(edge_type)
    return spec.category if spec else "unknown"


def edge_weight(edge_type: str) -> int:
    spec = EDGE_SPECS.get(edge_type)
    return spec.weight if spec else 1


def edge_prerequisites(edge_type: str) -> str:
    spec = EDGE_SPECS.get(edge_type)
    return spec.prerequisites if spec else ""


def edge_remediation(edge_type: str) -> str:
    spec = EDGE_SPECS.get(edge_type)
    return spec.remediation if spec else ""


def known_relationship_types() -> Iterable[str]:
    return EDGE_SPECS.keys()


def is_known(edge_type: str) -> bool:
    return edge_type in EDGE_SPECS

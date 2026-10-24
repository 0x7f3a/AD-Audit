"""Resolution of privileged targets.

Targets come from two places:

* A built-in table of well-known privileged groups (matched by domain-relative
  RID, so it works for any domain) and well-known local groups (matched by
  SID). These are *definitions*: a definition only becomes a target when a
  matching object exists in the analysed data, and the report says whether it
  was matched by SID or only by name.
* ``--target`` values supplied on the command line, which accept a SID, an
  object id, ``DOMAIN\\name``, or a plain name/SAM account name.

No target is ever invented. An unmatched definition is reported as not found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import DirectoryDataset, DirObject, Severity
from .normalize import dn_key, normalise_sid, split_identifier


@dataclass(frozen=True)
class TargetSpec:
    """A built-in privileged-target definition."""

    key: str
    label: str
    tier: int  # 0 = domain/enterprise control, 1 = delegated administration
    rationale: str
    rid: Optional[int] = None
    sid: Optional[str] = None
    name_keys: Tuple[str, ...] = ()
    object_type: str = "group"


DEFAULT_TARGET_SPECS: Tuple[TargetSpec, ...] = (
    TargetSpec(
        key="domain-admins",
        label="Domain Admins",
        rid=512,
        tier=0,
        rationale="members can administer the entire domain",
        name_keys=("domain admins",),
    ),
    TargetSpec(
        key="enterprise-admins",
        label="Enterprise Admins",
        rid=519,
        tier=0,
        rationale="members can administer every domain in the forest",
        name_keys=("enterprise admins",),
    ),
    TargetSpec(
        key="schema-admins",
        label="Schema Admins",
        rid=518,
        tier=0,
        rationale="members can modify the Active Directory schema",
        name_keys=("schema admins",),
    ),
    TargetSpec(
        key="administrators",
        label="Administrators",
        sid="S-1-5-32-544",
        tier=0,
        rationale="members hold full control over domain controllers",
        name_keys=("administrators",),
    ),
    TargetSpec(
        key="krbtgt",
        label="krbtgt",
        rid=502,
        tier=0,
        object_type="user",
        rationale="control of the krbtgt account allows forging authentication tickets",
        name_keys=("krbtgt",),
    ),
    TargetSpec(
        key="account-operators",
        label="Account Operators",
        rid=548,
        sid="S-1-5-32-548",
        tier=1,
        rationale="members can modify many user and group objects",
        name_keys=("account operators",),
    ),
    TargetSpec(
        key="server-operators",
        label="Server Operators",
        rid=549,
        sid="S-1-5-32-549",
        tier=1,
        rationale="members can administer domain controllers",
        name_keys=("server operators",),
    ),
    TargetSpec(
        key="backup-operators",
        label="Backup Operators",
        rid=551,
        sid="S-1-5-32-551",
        tier=1,
        rationale="members can back up and restore domain controller data",
        name_keys=("backup operators",),
    ),
    TargetSpec(
        key="print-operators",
        label="Print Operators",
        rid=550,
        sid="S-1-5-32-550",
        tier=1,
        rationale="members can load drivers on domain controllers",
        name_keys=("print operators",),
    ),
    TargetSpec(
        key="gpo-creators",
        label="Group Policy Creator Owners",
        rid=520,
        tier=1,
        rationale="members can create and modify Group Policy Objects",
        name_keys=("group policy creator owners",),
    ),
    TargetSpec(
        key="dns-admins",
        label="DnsAdmins",
        rid=1101,
        tier=1,
        rationale="members can influence the DNS service running on domain controllers",
        name_keys=("dnsadmins",),
    ),
    TargetSpec(
        key="key-admins",
        label="Key Admins",
        rid=526,
        tier=1,
        rationale="members can modify key credentials of privileged accounts",
        name_keys=("key admins",),
    ),
    TargetSpec(
        key="enterprise-key-admins",
        label="Enterprise Key Admins",
        rid=527,
        tier=1,
        rationale="members can modify key credentials across the forest",
        name_keys=("enterprise key admins",),
    ),
    TargetSpec(
        key="domain-controllers",
        label="Domain Controllers",
        rid=516,
        tier=1,
        rationale="membership is limited to domain controllers",
        name_keys=("domain controllers",),
    ),
)


@dataclass
class Target:
    """A target resolved against the analysed dataset."""

    id: str
    label: str
    name: str
    definition: str
    tier: int
    rationale: str
    matched_by: str  # "sid" | "name" | "cli"
    object_type: str = "group"

    @property
    def severity_floor(self) -> Severity:
        return Severity.HIGH if self.tier == 0 else Severity.MEDIUM

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "label": self.label,
            "definition": self.definition,
            "tier": self.tier,
            "rationale": self.rationale,
            "matched_by": self.matched_by,
            "object_type": self.object_type,
        }


@dataclass
class TargetResolution:
    targets: List[Target] = field(default_factory=list)
    unresolved_specs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    missing_defaults: List[str] = field(default_factory=list)

    @property
    def ids(self) -> List[str]:
        return [target.id for target in self.targets]

    def by_id(self) -> Dict[str, Target]:
        return {target.id: target for target in self.targets}

    def to_dict(self) -> List[Dict[str, object]]:
        return [target.to_dict() for target in self.targets]


def resolve_targets(
    dataset: DirectoryDataset,
    cli_targets: Sequence[str] = (),
    include_defaults: bool = True,
) -> TargetResolution:
    resolution = TargetResolution()
    seen: Dict[str, Target] = {}

    domain_sids = _domain_sids(dataset)

    if include_defaults:
        for spec in DEFAULT_TARGET_SPECS:
            matches = _match_spec(dataset, spec, domain_sids)
            if not matches:
                resolution.missing_defaults.append(spec.label)
                continue
            for obj, matched_by in matches:
                if obj.id in seen:
                    continue
                target = Target(
                    id=obj.id,
                    label=obj.label,
                    name=obj.name,
                    definition=spec.label,
                    tier=spec.tier,
                    rationale=spec.rationale,
                    matched_by=matched_by,
                    object_type=obj.type.value,
                )
                seen[obj.id] = target
                resolution.targets.append(target)
        for obj in dataset.objects.values():
            if obj.type.value == "domain":
                if obj.id in seen:
                    continue
                target = Target(
                    id=obj.id,
                    label=obj.label,
                    name=obj.name,
                    definition="Domain object",
                    tier=0,
                    rationale=(
                        "full control over the domain object includes directory "
                        "replication rights (DCSync) and permission changes"
                    ),
                    matched_by="sid" if obj.sid else "name",
                    object_type="domain",
                )
                seen[obj.id] = target
                resolution.targets.append(target)

    for spec in cli_targets:
        # Each flag value is one identifier: distinguished names contain commas.
        token = spec.strip()
        if not token:
            continue
        matches = _match_token(dataset, token)
        if not matches:
            resolution.unresolved_specs.append(token)
            continue
        for obj in matches:
            if obj.id in seen:
                # Already a target through the built-in table; keep the
                # definition but note that it was also requested.
                continue
            target = Target(
                id=obj.id,
                label=obj.label,
                name=obj.name,
                definition=f"CLI target: {token}",
                tier=0,
                rationale="selected explicitly as an assessment target",
                matched_by="cli",
                object_type=obj.type.value,
            )
            seen[obj.id] = target
            resolution.targets.append(target)

    if resolution.unresolved_specs:
        resolution.notes.append(
            "Requested targets that matched no object: "
            + ", ".join(sorted(resolution.unresolved_specs))
        )
    if not resolution.targets:
        resolution.notes.append(
            "No privileged targets could be resolved against the dataset. "
            "Supply --target with a SID, DN, or object name, or check that the "
            "export contains the privileged groups."
        )
    if resolution.missing_defaults and resolution.targets:
        resolution.notes.append(
            "Built-in targets not present in the dataset: "
            + ", ".join(resolution.missing_defaults)
        )
    by_name = [target.label for target in resolution.targets if target.matched_by == "name"]
    if by_name:
        resolution.notes.append(
            "Resolved by name rather than SID (weaker match): " + ", ".join(sorted(by_name))
        )

    resolution.targets.sort(key=lambda target: (target.tier, target.definition, target.label))
    return resolution


def _match_spec(
    dataset: DirectoryDataset,
    spec: TargetSpec,
    domain_sids: Iterable[str],
) -> List[Tuple[DirObject, str]]:
    matches: List[Tuple[DirObject, str]] = []
    sids = set()
    for domain_sid in domain_sids:
        if spec.rid is not None:
            sids.add(f"{domain_sid}-{spec.rid}")
    if spec.sid:
        sids.add(spec.sid.upper())

    for obj in dataset.objects.values():
        if obj.sid and obj.sid.upper() in sids:
            if spec.object_type == "user" and obj.type.value not in ("user", "unknown"):
                continue
            if spec.object_type == "group" and obj.type.value not in ("group", "unknown"):
                continue
            matches.append((obj, "sid"))

    if matches:
        return matches

    # Name-based fallback: only when the export carries no matching SIDs at all.
    for obj in dataset.objects.values():
        if obj.domain and obj.domain.lower() in obj.name.lower():
            continue
        if obj.name.lower() in spec.name_keys and obj.type.value in (spec.object_type, "unknown"):
            matches.append((obj, "name"))
    return matches


def _match_token(dataset: DirectoryDataset, token: str) -> List[DirObject]:
    sid = normalise_sid(token)
    if sid:
        return sorted(
            (obj for obj in dataset.objects.values() if obj.sid and obj.sid.upper() == sid),
            key=lambda obj: obj.id,
        )

    domain, name = split_identifier(token)
    lookup = dn_key(name) if "=" in name else name.strip().lower()
    candidates: List[DirObject] = []
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
            candidates.append(obj)
    return sorted(candidates, key=lambda obj: obj.id)


def _domain_matches(object_domain: str, requested: str) -> bool:
    """Allow both ``CORP`` and ``CORP.EXAMPLE`` as a domain prefix."""
    object_domain = object_domain.lower()
    requested = requested.lower()
    return object_domain == requested or object_domain.split(".", 1)[0] == requested


def _domain_sids(dataset: DirectoryDataset) -> List[str]:
    """Domain SIDs usable for domain-relative RID matching."""
    sids = set()
    for obj in dataset.objects.values():
        if obj.type.value == "domain" and obj.sid:
            sids.add(obj.sid.upper())
    if not sids:
        # Fall back to deriving from any domain object SID: S-1-5-21-a-b-c-RID
        for obj in dataset.objects.values():
            if not obj.sid:
                continue
            parts = obj.sid.split("-")
            if len(parts) >= 8 and parts[1:4] == ["1", "5", "21"]:
                sids.add("-".join(parts[:-1]))
    return sorted(sids)

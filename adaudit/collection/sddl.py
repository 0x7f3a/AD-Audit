"""Security descriptor parsing (SDDL and binary) for read-only collection.

Only the DACL is interpreted: allow-ACEs are mapped to AD-Audit relationship
types when the meaning is unambiguous. Anything else (deny ACEs, read-only
rights, key-credential writes) is counted as unmapped and reported, never
converted into a guessed privilege.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..normalize import normalise_guid, normalise_sid

# --- access mask bits ------------------------------------------------------
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_PROPERTY = 0x00000020
READ_PROPERTY = 0x00000010
SELF = 0x00000008
CONTROL_ACCESS = 0x00000100

_RIGHT_TOKENS = {
    "GA": GENERIC_ALL,
    "GR": 0x80000000,
    "GW": GENERIC_WRITE,
    "GX": 0x20000000,
    "RC": READ_CONTROL,
    "SD": DELETE,
    "WD": WRITE_DAC,
    "WO": WRITE_OWNER,
    "CC": 0x00000001,
    "DC": 0x00000002,
    "LC": 0x00000004,
    "SW": SELF,
    "RP": READ_PROPERTY,
    "WP": WRITE_PROPERTY,
    "DT": 0x00000040,
    "LO": 0x00000080,
    "CR": CONTROL_ACCESS,
}

# --- well-known extended rights / attribute GUIDs --------------------------
FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
USER_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"
DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
ATTRIBUTE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
ATTRIBUTE_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
ATTRIBUTE_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

_DCSYNC_RIGHTS = frozenset(
    {
        DS_REPLICATION_GET_CHANGES,
        DS_REPLICATION_GET_CHANGES_ALL,
        DS_REPLICATION_GET_CHANGES_FILTERED,
    }
)


class SecurityDescriptorError(ValueError):
    """Raised when a security descriptor cannot be parsed."""


@dataclass(frozen=True)
class AceGrant:
    """One DACL entry, normalised but not yet mapped to a relationship."""

    sid: str
    mask: int
    allowed: bool = True
    inherited: bool = False
    object_guid: Optional[str] = None

    @property
    def is_deny(self) -> bool:
        return not self.allowed


# ---------------------------------------------------------------------------
# SDDL
# ---------------------------------------------------------------------------


def parse_sddl(text: str) -> List[AceGrant]:
    """Parse the DACL of an SDDL string into :class:`AceGrant` records."""
    if not isinstance(text, str) or not text.strip():
        raise SecurityDescriptorError("empty SDDL string")
    if "D:" not in text:
        return []
    dacl = _dacl_section(text)
    grants: List[AceGrant] = []
    for raw in re.findall(r"\(([^()]*)\)", dacl):
        fields = raw.split(";")
        if len(fields) < 6:
            raise SecurityDescriptorError(f"malformed ACE: ({raw})")
        ace_type, flags, rights, object_guid, _inherited_guid, sid = fields[:6]
        if ace_type not in ("A", "D", "OA", "OD"):
            continue  # audit ACEs are not permissions
        mask = _parse_rights(rights)
        sid_text = normalise_sid(sid)
        if sid_text is None:
            raise SecurityDescriptorError(f"ACE contains an invalid SID: {sid!r}")
        grants.append(
            AceGrant(
                sid=sid_text,
                mask=mask,
                allowed=ace_type in ("A", "OA"),
                inherited="ID" in flags.upper(),
                object_guid=normalise_guid(object_guid),
            )
        )
    return grants


def _dacl_section(text: str) -> str:
    start = text.index("D:")
    remainder = text[start + 2 :]
    cut = len(remainder)
    for marker in ("S:", "O:", "G:"):
        index = remainder.find(marker)
        if index != -1:
            cut = min(cut, index)
    return remainder[:cut]


def _parse_rights(rights: str) -> int:
    text = rights.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    mask = 0
    if len(text) % 2 != 0:
        raise SecurityDescriptorError(f"malformed access rights: {rights!r}")
    for index in range(0, len(text), 2):
        token = text[index : index + 2].upper()
        if token not in _RIGHT_TOKENS:
            raise SecurityDescriptorError(f"unknown access-right token: {token!r}")
        mask |= _RIGHT_TOKENS[token]
    return mask


# ---------------------------------------------------------------------------
# Binary security descriptor
# ---------------------------------------------------------------------------

SE_DACL_PRESENT = 0x0004
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
OBJECT_ACE_TYPES = frozenset({0x05, 0x06, 0x0B, 0x0C})
ACE_FLAG_INHERITED = 0x10


def parse_security_descriptor(data: bytes) -> List[AceGrant]:
    """Parse a self-relative binary security descriptor's DACL."""
    if not isinstance(data, (bytes, bytearray)):
        raise SecurityDescriptorError("security descriptor must be bytes")
    data = bytes(data)
    if len(data) < 20:
        raise SecurityDescriptorError("security descriptor is shorter than its header")
    control = int.from_bytes(data[2:4], "little")
    dacl_offset = int.from_bytes(data[16:20], "little")
    if not control & SE_DACL_PRESENT or dacl_offset == 0:
        return []
    if dacl_offset + 8 > len(data):
        raise SecurityDescriptorError("DACL offset is outside the descriptor")

    ace_count = int.from_bytes(data[dacl_offset + 4 : dacl_offset + 6], "little")
    position = dacl_offset + 8
    grants: List[AceGrant] = []
    for _ in range(ace_count):
        if position + 8 > len(data):
            raise SecurityDescriptorError("truncated ACE list")
        ace_type = data[position]
        ace_flags = data[position + 1]
        ace_size = int.from_bytes(data[position + 2 : position + 4], "little")
        if ace_size < 8 or position + ace_size > len(data):
            raise SecurityDescriptorError("invalid ACE size")
        mask = int.from_bytes(data[position + 4 : position + 8], "little")
        cursor = position + 8
        object_guid: Optional[str] = None
        if ace_type in OBJECT_ACE_TYPES:
            if cursor + 4 > position + ace_size:
                raise SecurityDescriptorError("truncated object ACE")
            object_flags = int.from_bytes(data[cursor : cursor + 4], "little")
            cursor += 4
            if object_flags & 0x1:
                if cursor + 16 > position + ace_size:
                    raise SecurityDescriptorError("truncated object GUID")
                object_guid = normalise_guid(uuid.UUID(bytes_le=data[cursor : cursor + 16]))
                cursor += 16
            if object_flags & 0x2:
                cursor += 16  # inherited-object-type GUID: not needed here
        sid_text, _ = _sid_from_bytes(data, cursor, position + ace_size)
        grants.append(
            AceGrant(
                sid=sid_text,
                mask=mask,
                allowed=ace_type != ACE_TYPE_ACCESS_DENIED,
                inherited=bool(ace_flags & ACE_FLAG_INHERITED),
                object_guid=object_guid,
            )
        )
        position += ace_size
    return grants


def parse_owner(data: bytes) -> Optional[str]:
    """Return the owner SID of a binary security descriptor, if present."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 20:
        return None
    data = bytes(data)
    owner_offset = int.from_bytes(data[4:8], "little")
    if owner_offset == 0 or owner_offset + 8 > len(data):
        return None
    try:
        sid_text, _ = _sid_from_bytes(data, owner_offset, len(data))
    except SecurityDescriptorError:
        return None
    return sid_text


def _sid_from_bytes(data: bytes, offset: int, limit: int) -> Tuple[str, int]:
    if offset + 8 > limit or offset + 8 > len(data):
        raise SecurityDescriptorError("truncated SID")
    revision = data[offset]
    count = data[offset + 1]
    length = 8 + 4 * count
    if offset + length > limit or offset + length > len(data):
        raise SecurityDescriptorError("SID length exceeds the ACE")
    authority = int.from_bytes(data[offset + 2 : offset + 8], "big")
    sub_authorities = [
        int.from_bytes(data[offset + 8 + 4 * index : offset + 12 + 4 * index], "little")
        for index in range(count)
    ]
    text = f"S-{revision}-{authority}" + "".join(f"-{value}" for value in sub_authorities)
    return normalise_sid(text) or text, length


# ---------------------------------------------------------------------------
# Mapping to relationships
# ---------------------------------------------------------------------------


def map_grant(grant: AceGrant, target_type: str) -> Optional[str]:
    """Map a DACL entry to an AD-Audit relationship type, or ``None``.

    ``target_type`` is the object class of the object carrying the ACE, because
    the same right means different things on a group, a user or the domain.
    """
    if grant.is_deny:
        return None
    mask = grant.mask
    if mask & GENERIC_ALL:
        return "GenericAll"
    if mask & WRITE_DAC:
        return "WriteDacl"
    if mask & WRITE_OWNER:
        return "WriteOwner"
    guid = grant.object_guid
    if mask & WRITE_PROPERTY:
        if guid == ATTRIBUTE_MEMBER and target_type == "group":
            return "AddMember"
        if guid == ATTRIBUTE_ALLOWED_TO_ACT:
            return "AllowedToAct"
        if guid == ATTRIBUTE_KEY_CREDENTIAL_LINK:
            return None  # shadow-credential technique; deliberately not modelled
        return "GenericWrite"
    if mask & CONTROL_ACCESS:
        if guid == FORCE_CHANGE_PASSWORD and target_type in ("user", "computer"):
            return "ForceChangePassword"
        if guid in _DCSYNC_RIGHTS and target_type == "domain":
            return "DCSync"
        if guid is None:
            return "AllExtendedRights"
        return None
    if mask & GENERIC_WRITE:
        return "GenericWrite"
    return None


def describe_grant(grant: AceGrant, relationship: Optional[str]) -> str:
    parts = [f"DACL {'deny' if grant.is_deny else 'allow'} mask 0x{grant.mask:08x}"]
    if grant.object_guid:
        parts.append(f"object GUID {grant.object_guid}")
    if grant.inherited:
        parts.append("inherited")
    if relationship:
        parts.append(f"mapped to {relationship}")
    else:
        parts.append("not mapped to a relationship")
    return ", ".join(parts)


def describe_allowed_to_act(data: bytes) -> List[str]:
    """Principals allowed to act on behalf of a computer (RBCD attribute)."""
    sids: List[str] = []
    for grant in parse_security_descriptor(data):
        if grant.is_deny:
            continue
        if grant.mask & GENERIC_ALL or grant.mask & CONTROL_ACCESS:
            sids.append(grant.sid)
    return sorted(set(sids))

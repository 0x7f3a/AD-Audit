"""Normalisation helpers shared by every importer.

Directory data rarely agrees with itself: SIDs appear with inconsistent case,
distinguished names carry escaped commas, GUIDs arrive in braces, and the same
account may be exported once with and once without a domain prefix. These
helpers give the importers one consistent interpretation without guessing.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

_SID_RE = re.compile(r"^S-1-(?:[0-9]+-){0,14}[0-9]+$", re.IGNORECASE)
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def normalise_sid(value: object) -> Optional[str]:
    """Return an upper-case SID, or ``None`` when the value is not a SID."""
    if value is None:
        return None
    text = str(value).strip()
    if text.upper().startswith("S-1-5-21-"):
        pass
    elif not text.upper().startswith("S-1-"):
        return None
    text = text.upper()
    if not _SID_RE.match(text):
        return None
    return text


def normalise_guid(value: object) -> Optional[str]:
    """Return a lower-case GUID in canonical form (no braces), or ``None``."""
    if value is None:
        return None
    text = str(value).strip().strip("{}").lower()
    if not _GUID_RE.match(text):
        return None
    return text


def normalise_domain(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().strip(".").lower()
    return text or None


def normalise_name(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def split_dn(dn: str) -> List[str]:
    """Split a distinguished name on unescaped commas."""
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    for char in dn:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == ",":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parent_dn(dn: Optional[str]) -> Optional[str]:
    """Return the immediate parent container DN, or ``None`` at the root."""
    if not dn:
        return None
    parts = split_dn(dn)
    if len(parts) <= 1:
        return None
    return ",".join(parts[1:])


def normalise_dn(dn: object) -> Optional[str]:
    """Normalise whitespace and case of the attribute names only.

    Values keep their case (distinguished names are case-insensitive, but the
    report should show what was collected), while attribute names are folded to
    lower case so two records can be compared.
    """
    if dn is None:
        return None
    text = str(dn).strip()
    if not text:
        return None
    normalised_parts: List[str] = []
    for part in split_dn(text):
        if "=" in part:
            attribute, _, value = part.partition("=")
            normalised_parts.append(f"{attribute.strip().lower()}={value.strip()}")
        else:
            normalised_parts.append(part)
    return ",".join(normalised_parts)


def dn_key(dn: object) -> Optional[str]:
    """Comparison key for a DN (case-insensitive, attribute names folded)."""
    normalised = normalise_dn(dn)
    return normalised.lower() if normalised else None


def domain_from_dn(dn: Optional[str]) -> Optional[str]:
    """Extract ``corp.example`` from ``DC=corp,DC=example`` style names."""
    if not dn:
        return None
    labels: List[str] = []
    for part in split_dn(dn):
        attribute, _, value = part.partition("=")
        if attribute.strip().lower() == "dc" and value:
            labels.append(value.strip())
    if not labels:
        return None
    return normalise_domain(".".join(labels))


def object_type_from_dn(dn: Optional[str]) -> Optional[str]:
    """Best-effort object class hint from a distinguished name."""
    if not dn:
        return None
    parts = split_dn(dn)
    if not parts:
        return None
    first = parts[0].partition("=")
    attribute = first[0].strip().lower()
    if attribute == "ou":
        return "ou"
    if attribute == "dc":
        return "domain"
    return None


def canonical_object_id(
    sid: Optional[str],
    dn: Optional[str],
    domain: Optional[str],
    name: Optional[str],
) -> Optional[str]:
    """Stable identifier for an object: SID, else DN, else ``name@domain``.

    Using the SID first means a renamed object keeps its identity, and a user
    and a group with the same common name never collide.
    """
    if sid:
        return sid
    if dn:
        key = dn_key(dn)
        if key:
            return f"dn:{key}"
    if name and domain:
        return f"name:{str(name).strip().lower()}@{domain}"
    if name:
        return f"name:{str(name).strip().lower()}"
    return None


def looks_like_sid(value: object) -> bool:
    return normalise_sid(value) is not None


def dedupe_preserving_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def split_identifier(value: str) -> Tuple[Optional[str], str]:
    """Split ``DOMAIN\\name`` into (domain, name); domain may be ``None``."""
    if "\\" in value:
        domain, _, name = value.partition("\\")
        return (normalise_domain(domain), name.strip())
    return (None, value.strip())

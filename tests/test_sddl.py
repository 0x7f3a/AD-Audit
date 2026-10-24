"""Security descriptor parsing: precise mappings, explicit non-mappings."""

from __future__ import annotations

import struct
from typing import Optional

import pytest

from adaudit.collection import sddl

SID = "S-1-5-21-1-2-3-1105"
GROUP = "S-1-5-21-1-2-3-1120"


def sddl_dacl(*aces: str) -> str:
    return "O:S-1-5-21-1-2-3-500G:S-1-5-21-1-2-3-513D:" + "".join(f"({ace})" for ace in aces)


def sid_bytes(sid_text: str) -> bytes:
    parts = sid_text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(part) for part in parts[3:]]
    return (
        struct.pack("<BB", revision, len(sub_authorities))
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", value) for value in sub_authorities)
    )


def build_descriptor(mask: int = sddl.GENERIC_ALL, flags: int = 0, owner: Optional[str] = None) -> bytes:
    sid = sid_bytes(SID)
    ace = struct.pack("<BBHI", 0x00, flags, 8 + len(sid), mask) + sid
    dacl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    owner_offset = 20 + len(dacl) if owner else 0
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, owner_offset, 0, 0, 20)
    payload = header + dacl
    if owner:
        payload += sid_bytes(owner)
    return payload


def test_parse_sddl_single_allow_ace():
    grants = sddl.parse_sddl(sddl_dacl(f"A;;GA;;;{SID}"))
    assert len(grants) == 1
    grant = grants[0]
    assert grant.sid == SID
    assert grant.allowed is True
    assert grant.inherited is False
    assert grant.mask & sddl.GENERIC_ALL


def test_parse_sddl_inherited_flag():
    grants = sddl.parse_sddl(sddl_dacl(f"A;ID;GA;;;{SID}"))
    assert grants[0].inherited is True


def test_parse_sddl_deny_and_extended_right():
    grants = sddl.parse_sddl(
        sddl_dacl(f"D;;GA;;;{SID}", f"OA;;CR;{sddl.FORCE_CHANGE_PASSWORD};;{SID}")
    )
    assert grants[0].is_deny is True
    assert grants[1].object_guid == sddl.FORCE_CHANGE_PASSWORD


def test_parse_sddl_hex_mask():
    grants = sddl.parse_sddl(sddl_dacl(f"A;;0x000F01FF;;;{SID}"))
    assert grants[0].mask == 0x000F01FF


def test_parse_sddl_ignores_audit_aces():
    assert sddl.parse_sddl(sddl_dacl(f"AU;SA;GA;;;{SID}")) == []


def test_parse_sddl_rejects_unknown_token_and_bad_sid():
    with pytest.raises(sddl.SecurityDescriptorError):
        sddl.parse_sddl(sddl_dacl(f"A;;ZZ;;;{SID}"))
    with pytest.raises(sddl.SecurityDescriptorError):
        sddl.parse_sddl(sddl_dacl("A;;GA;;;not-a-sid"))


def test_parse_sddl_with_sacl_section():
    text = sddl_dacl(f"A;;GA;;;{SID}") + "S:(AU;SA;GA;;;WD)"
    grants = sddl.parse_sddl(text)
    assert len(grants) == 1


def test_map_generic_all_and_deny():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;GA;;;{SID}"))[0]
    assert sddl.map_grant(grant, "group") == "GenericAll"
    deny = sddl.parse_sddl(sddl_dacl(f"D;;GA;;;{SID}"))[0]
    assert sddl.map_grant(deny, "group") is None


def test_map_write_dacl_and_write_owner():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;WD;;;{SID}"))[0]
    assert sddl.map_grant(grant, "user") == "WriteDacl"
    grant = sddl.parse_sddl(sddl_dacl(f"A;;WO;;;{SID}"))[0]
    assert sddl.map_grant(grant, "user") == "WriteOwner"


def test_map_generic_write():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;GW;;;{SID}"))[0]
    assert sddl.map_grant(grant, "user") == "GenericWrite"


def test_map_member_attribute_depends_on_target_type():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;WP;{sddl.ATTRIBUTE_MEMBER};;{SID}"))[0]
    assert sddl.map_grant(grant, "group") == "AddMember"
    assert sddl.map_grant(grant, "user") == "GenericWrite"


def test_map_force_change_password_only_for_accounts():
    grant = sddl.parse_sddl(
        sddl_dacl(f"OA;;CR;{sddl.FORCE_CHANGE_PASSWORD};;{SID}")
    )[0]
    assert sddl.map_grant(grant, "user") == "ForceChangePassword"
    assert sddl.map_grant(grant, "group") is None


def test_map_dcsync_only_for_domain():
    grant = sddl.parse_sddl(
        sddl_dacl(f"OA;;CR;{sddl.DS_REPLICATION_GET_CHANGES_ALL};;{SID}")
    )[0]
    assert sddl.map_grant(grant, "domain") == "DCSync"
    assert sddl.map_grant(grant, "user") is None


def test_map_all_extended_rights():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;CR;;;{SID}"))[0]
    assert sddl.map_grant(grant, "user") == "AllExtendedRights"


def test_map_allowed_to_act_attribute():
    grant = sddl.parse_sddl(
        sddl_dacl(f"A;;WP;{sddl.ATTRIBUTE_ALLOWED_TO_ACT};;{SID}")
    )[0]
    assert sddl.map_grant(grant, "computer") == "AllowedToAct"


def test_unmodelled_writes_are_not_converted():
    grant = sddl.parse_sddl(
        sddl_dacl(f"A;;WP;{sddl.ATTRIBUTE_KEY_CREDENTIAL_LINK};;{SID}")
    )[0]
    assert sddl.map_grant(grant, "user") is None
    read_only = sddl.parse_sddl(sddl_dacl(f"A;;RP;;;{SID}"))[0]
    assert sddl.map_grant(read_only, "user") is None


def test_parse_binary_descriptor():
    grants = sddl.parse_security_descriptor(build_descriptor(flags=0x10))
    assert len(grants) == 1
    assert grants[0].sid == SID
    assert grants[0].inherited is True
    assert grants[0].allowed is True
    assert sddl.map_grant(grants[0], "user") == "GenericAll"


def test_parse_binary_descriptor_without_dacl_is_empty():
    header = struct.pack("<BBHIIII", 1, 0, 0x0000, 0, 0, 0, 0)
    assert sddl.parse_security_descriptor(header) == []


def test_parse_owner():
    descriptor = build_descriptor(owner="S-1-5-21-1-2-3-500")
    assert sddl.parse_owner(descriptor) == "S-1-5-21-1-2-3-500"


def test_parse_owner_absent():
    assert sddl.parse_owner(build_descriptor()) is None
    assert sddl.parse_owner(b"short") is None


def test_describe_allowed_to_act():
    descriptor = build_descriptor()
    assert sddl.describe_allowed_to_act(descriptor) == [SID]


def test_truncated_descriptor_raises():
    with pytest.raises(sddl.SecurityDescriptorError):
        sddl.parse_security_descriptor(b"\x01\x00\x04\x80")


def test_describe_grant_mentions_mapping():
    grant = sddl.parse_sddl(sddl_dacl(f"A;;GA;;;{SID}"))[0]
    text = sddl.describe_grant(grant, "GenericAll")
    assert "GenericAll" in text
    assert "0x10000000" in text


def test_group_sids_are_not_confused_with_users():
    grants = sddl.parse_sddl(sddl_dacl(f"A;;GA;;;{GROUP}"))
    assert grants[0].sid == GROUP

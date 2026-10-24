"""Normalisation helpers must be strict: no guessing, no silent coercion."""

from __future__ import annotations

from adaudit.normalize import (
    canonical_object_id,
    dn_key,
    domain_from_dn,
    normalise_dn,
    normalise_guid,
    normalise_sid,
    parent_dn,
    split_dn,
    split_identifier,
)


def test_normalise_sid_accepts_and_folds_case():
    assert normalise_sid("s-1-5-21-1-2-3-512") == "S-1-5-21-1-2-3-512"
    assert normalise_sid("  S-1-5-32-544 ") == "S-1-5-32-544"


def test_normalise_sid_rejects_non_sids():
    assert normalise_sid("Domain Admins") is None
    assert normalise_sid("") is None
    assert normalise_sid(None) is None
    assert normalise_sid("S-1-") is None


def test_normalise_guid_strips_braces_and_folds_case():
    assert normalise_guid("{1A2B3C4D-5E6F-4A7B-8C9D-0E1F2A3B4C5D}") == (
        "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    )
    assert normalise_guid("not-a-guid") is None


def test_split_dn_respects_escaped_commas():
    dn = r"CN=Doe\, John,OU=Staff,DC=corp,DC=example"
    assert split_dn(dn) == [r"CN=Doe\, John", "OU=Staff", "DC=corp", "DC=example"]
    assert parent_dn(dn) == "OU=Staff,DC=corp,DC=example"


def test_parent_dn_of_root_is_none():
    assert parent_dn("DC=corp,DC=example") == "DC=example"
    assert parent_dn("DC=example") is None
    assert parent_dn(None) is None


def test_domain_from_dn():
    assert domain_from_dn("CN=Analyst,OU=Staff,DC=corp,DC=example") == "corp.example"
    assert domain_from_dn("OU=Staff") is None


def test_normalise_dn_folds_attribute_names_only():
    assert normalise_dn("CN=Analyst,DC=Corp,DC=Example") == "cn=Analyst,dc=Corp,dc=Example"
    assert dn_key("CN=Analyst,DC=Corp,DC=Example") == "cn=analyst,dc=corp,dc=example"


def test_canonical_object_id_prefers_sid_then_dn_then_name():
    sid = "S-1-5-21-1-2-3-1105"
    assert canonical_object_id(sid, "CN=A,DC=x", "x", "A") == sid
    assert canonical_object_id(None, "CN=A,DC=X", None, "A") == "dn:cn=a,dc=x"
    assert canonical_object_id(None, None, "corp.example", "Analyst") == "name:analyst@corp.example"
    assert canonical_object_id(None, None, None, "Analyst") == "name:analyst"
    assert canonical_object_id(None, None, None, None) is None


def test_split_identifier_handles_domain_prefix():
    assert split_identifier(r"CORP\analyst") == ("corp", "analyst")
    assert split_identifier("analyst") == (None, "analyst")

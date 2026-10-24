"""BloodHound import: tolerated formats, explicit gaps, no invented edges."""

from __future__ import annotations

import json

import pytest

from adaudit.importers import DatasetImportError, load_dataset
from adaudit.models import ObjectType

from support import (
    DOMAIN_SID,
    bh_ace,
    bh_group,
    bh_member,
    bh_props,
    bh_user,
    sid,
    write_bh_export,
    zip_bh_export,
)


def basic_files():
    return {
        "users.json": [
            bh_user(1105, "analyst", "CN=Analyst,OU=Staff,DC=corp,DC=example"),
            bh_user(500, "Administrator", "CN=Administrator,CN=Users,DC=corp,DC=example"),
        ],
        "groups.json": [
            bh_group(
                512,
                "Domain Admins",
                "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                members=[bh_member(sid(500))],
            ),
            bh_group(
                1120,
                "Helpdesk",
                "CN=Helpdesk,OU=Groups,DC=corp,DC=example",
                members=[bh_member(sid(1105))],
            ),
        ],
        "computers.json": [
            {
                "ObjectIdentifier": sid(1201),
                "Properties": bh_props("WS01", "CN=WS01,OU=Workstations,DC=corp,DC=example", sid(1201)),
                "LocalAdmins": [{"ObjectIdentifier": sid(512), "ObjectType": "Group"}],
                "Sessions": [{"UserSID": sid(1105), "ComputerSID": sid(1201)}],
                "Aces": [bh_ace(sid(1120), "GenericAll", inherited=True)],
            }
        ],
        "domains.json": [
            {
                "ObjectIdentifier": DOMAIN_SID,
                "Properties": bh_props("CORP.EXAMPLE", "DC=corp,DC=example", DOMAIN_SID),
                "Aces": [bh_ace(sid(1120), "DCSync")],
                "Links": [],
            }
        ],
    }


def edge_types(dataset):
    return {(edge.type, edge.source, edge.target) for edge in dataset.edges}


def test_directory_export_builds_nodes_and_typed_edges(tmp_path, example_export):
    dataset = load_dataset([str(example_export)])

    assert dataset.collection.format == "bloodhound"
    assert dataset.collection.target_domain == "corp.example"
    assert dataset.object_type_counts()["user"] == 7
    assert dataset.object_type_counts()["domain"] == 1
    assert ("MemberOf", sid(1105), sid(1120)) in edge_types(dataset)
    # Session is stored as host -> user: compromising the host exposes the user.
    assert ("Session", sid(1202), sid(1105)) in edge_types(dataset)
    assert ("AdminTo", sid(1120), sid(1202)) in edge_types(dataset)
    assert ("AdminTo", sid(512), sid(1201)) in edge_types(dataset)
    assert ("GPOAppliesTo", "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", DOMAIN_SID) in edge_types(dataset)
    assert ("DCSync", sid(1121), DOMAIN_SID) in edge_types(dataset)


def test_inherited_ace_is_marked_derived(tmp_path):
    dataset = load_dataset([str(write_bh_export(tmp_path, basic_files()))])
    matches = [edge for edge in dataset.edges if edge.type == "GenericAll"]
    assert len(matches) == 1
    assert matches[0].inherited is True
    assert matches[0].quality.value == "derived"


def test_membership_direction_and_primary_group(tmp_path):
    dataset = load_dataset([str(write_bh_export(tmp_path, basic_files()))])
    assert ("MemberOf", sid(1105), sid(1120)) in edge_types(dataset)
    assert ("MemberOf", sid(1120), sid(1105)) not in edge_types(dataset)


def test_zip_and_directory_imports_match(tmp_path):
    files = basic_files()
    directory = load_dataset([str(write_bh_export(tmp_path, files))])
    archive = load_dataset([str(zip_bh_export(tmp_path, files))])
    assert set(directory.objects) == set(archive.objects)
    assert edge_types(directory) == edge_types(archive)


def test_combined_single_json_document(tmp_path):
    payload = {name.replace(".json", ""): records for name, records in basic_files().items()}
    path = tmp_path / "combined.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    dataset = load_dataset([str(path)])
    assert dataset.collection.format == "bloodhound"
    assert "MemberOf" in {edge.type for edge in dataset.edges}


def test_duplicate_objects_merge_and_conflicts_are_recorded(tmp_path):
    files = basic_files()
    first = bh_user(1105, "analyst", "CN=Analyst,OU=Staff,DC=corp,DC=example", highvalue=True)
    second = bh_user(1105, "analyst", "CN=Analyst,OU=Staff,DC=corp,DC=example", highvalue=False)
    files["users.json"] = [first, second]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert dataset.object_type_counts()["user"] == 1
    user = dataset.objects[sid(1105)]
    assert "conflicts" in user.attributes
    assert user.attributes["conflicts"]["highvalue"] == [True, False]


def test_duplicate_membership_is_one_edge(tmp_path):
    files = basic_files()
    files["groups.json"][1]["Members"] = [bh_member(sid(1105)), bh_member(sid(1105))]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    membership = [edge for edge in dataset.edges if edge.type == "MemberOf" and edge.source == sid(1105)]
    assert len(membership) == 1


def test_unmodelled_and_unknown_rights_are_reported_not_modelled(tmp_path):
    files = basic_files()
    files["computers.json"][0]["Aces"] = [
        bh_ace(sid(1120), "AddKeyCredentialLink"),
        bh_ace(sid(1120), "TotallyMadeUpRight"),
    ]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    codes = {issue.code for issue in dataset.issues}
    assert "unsupported-rights" in codes
    message = next(issue.message for issue in dataset.issues if issue.code == "unsupported-rights")
    assert "AddKeyCredentialLink" in message
    assert "TotallyMadeUpRight" in message
    assert not any(edge.type in ("AddKeyCredentialLink", "TotallyMadeUpRight") for edge in dataset.edges)


def test_unresolved_ace_principal_becomes_explicit_placeholder(tmp_path):
    files = basic_files()
    files["computers.json"][0]["Aces"] = [bh_ace("S-1-5-21-9-9-9-4242", "GenericAll")]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    placeholder = dataset.objects["S-1-5-21-9-9-9-4242"]
    assert placeholder.type is ObjectType.UNKNOWN
    assert placeholder.attributes["unresolved"] is True
    assert any(issue.code == "unresolved-principal" for issue in dataset.issues)


def test_malformed_record_is_an_error_not_a_crash(tmp_path):
    files = basic_files()
    files["users.json"].append("not-a-record")
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert any(issue.level == "error" and issue.code == "malformed-record" for issue in dataset.issues)
    assert dataset.collection.complete is False


def test_record_without_identifier_is_reported(tmp_path):
    files = basic_files()
    files["users.json"].append({"Properties": {}})
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert any(issue.code == "record-missing-identifier" for issue in dataset.issues)


def test_record_with_only_a_name_is_kept_under_a_name_id(tmp_path):
    files = basic_files()
    files["users.json"].append({"Properties": {"name": "ghost@corp.example"}})
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert any(object_id.startswith("name:") for object_id in dataset.objects)


def test_gpo_link_to_uncollected_policy_is_reported(tmp_path):
    files = basic_files()
    files["domains.json"][0]["Links"] = [{"GUID": "{ABCDEF01-2345-6789-ABCD-EF0123456789}"}]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert any(issue.code == "gpo-not-collected" for issue in dataset.issues)
    assert not any(edge.type == "GPOAppliesTo" for edge in dataset.edges)


def test_unsupported_export_files_are_reported(tmp_path):
    files = basic_files()
    files["certificates.json"] = [{"ObjectIdentifier": "S-1-5-21-1-2-3-9"}]
    dataset = load_dataset([str(zip_bh_export(tmp_path, files))])
    assert any(issue.code == "unsupported-export-file" for issue in dataset.issues)


def test_trusts_are_reported_as_a_gap(tmp_path):
    files = basic_files()
    files["domains.json"][0]["Trusts"] = [{"TargetDomainSid": "S-1-5-21-1-2-3"}]
    dataset = load_dataset([str(write_bh_export(tmp_path, files))])
    assert any(issue.code == "trusts-not-modelled" for issue in dataset.issues)
    assert any("trust" in gap.lower() for gap in dataset.collection.gaps)


def test_structural_containment_is_derived_from_dns(tmp_path, example_export):
    dataset = load_dataset([str(example_export)])
    containment = [edge for edge in dataset.edges if edge.type == "Contains"]
    assert containment
    assert all(edge.quality.value == "derived" for edge in containment)


def test_unsupported_file_type_raises_clear_error(tmp_path):
    path = tmp_path / "objects.csv"
    path.write_text("name,sid\n", encoding="utf-8")
    with pytest.raises(DatasetImportError) as excinfo:
        load_dataset([str(path)])
    assert "not supported" in str(excinfo.value)


def test_invalid_json_raises_clear_error(tmp_path):
    path = tmp_path / "users.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(DatasetImportError) as excinfo:
        load_dataset([str(path)])
    assert "invalid JSON" in str(excinfo.value)


def test_missing_input_raises(tmp_path):
    with pytest.raises(DatasetImportError) as excinfo:
        load_dataset([str(tmp_path / "nope.zip")])
    assert "not found" in str(excinfo.value)


def test_unknown_format_choice_is_rejected(tmp_path):
    with pytest.raises(DatasetImportError):
        load_dataset([str(tmp_path)], fmt="nessus")

"""Native export: strict validation, round-trip fidelity, no silent drops."""

from __future__ import annotations


import pytest

from adaudit.analysis import AnalysisConfig, analyse
from adaudit.export import to_payload
from adaudit.importers import DatasetImportError, load_dataset

from support import (
    load_payload,
    native_domain,
    native_group,
    native_payload,
    native_user,
    relationship,
    sid,
    write_json,
)


def test_round_trip_preserves_graph_and_findings(tmp_path, example_export):
    original = load_dataset([str(example_export)])
    payload = to_payload(original)
    assert payload["schema_version"] == "1.0"
    path = write_json(tmp_path, payload, "native.json")

    restored = load_dataset([str(path)], fmt="adaudit")
    assert set(restored.objects) == set(original.objects)
    assert {(edge.type, edge.source, edge.target) for edge in restored.edges} == {
        (edge.type, edge.source, edge.target) for edge in original.edges
    }

    first = analyse(original, AnalysisConfig())
    second = analyse(restored, AnalysisConfig())
    assert [finding.id for finding in first.findings] == [
        finding.id for finding in second.findings
    ]


def test_target_can_be_a_distinguished_name_with_commas(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst", dn="CN=Analyst,OU=Staff,DC=corp,DC=example")]
    )
    dataset = load_payload(tmp_path, payload)
    from adaudit.targets import resolve_targets

    resolution = resolve_targets(
        dataset,
        cli_targets=["CN=Analyst,OU=Staff,DC=corp,DC=example"],
        include_defaults=False,
    )
    assert [target.id for target in resolution.targets] == [sid(1105)]


def test_unknown_relationship_is_rejected(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()],
        [relationship("MagicEscalation", sid(1105), sid(512))],
    )
    dataset = load_payload(tmp_path, payload)
    assert dataset.edges == []
    assert any(
        issue.code == "unknown-relationship" and issue.level == "error"
        for issue in dataset.issues
    )
    assert dataset.collection.complete is False


def test_relationship_with_missing_endpoint_is_rejected(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst")],
        [relationship("MemberOf", sid(1105), sid(512))],
    )
    dataset = load_payload(tmp_path, payload)
    assert dataset.edges == []
    assert any(issue.code == "relationship-unknown-endpoint" for issue in dataset.issues)


def test_self_relationship_is_skipped(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst")],
        [relationship("MemberOf", sid(1105), sid(1105))],
    )
    dataset = load_payload(tmp_path, payload)
    assert dataset.edges == []
    assert any(issue.code == "self-relationship" for issue in dataset.issues)


def test_malformed_object_is_reported(tmp_path):
    payload = native_payload([native_user(1105, "analyst"), "not-an-object"])
    dataset = load_payload(tmp_path, payload)
    assert any(issue.code == "malformed-object" for issue in dataset.issues)


def test_missing_objects_array_raises(tmp_path):
    path = write_json(tmp_path, {"relationships": []})
    with pytest.raises(DatasetImportError) as excinfo:
        load_dataset([str(path)], fmt="adaudit")
    assert "'objects' must be a JSON array" in str(excinfo.value)


def test_schema_mismatch_is_a_warning(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst")],
        schema_version="9.0",
    )
    dataset = load_payload(tmp_path, payload)
    assert any(issue.code == "schema-version-mismatch" for issue in dataset.issues)


def test_missing_schema_version_is_a_note(tmp_path):
    payload = native_payload([native_user(1105, "analyst")])
    payload.pop("schema_version")
    dataset = load_payload(tmp_path, payload)
    assert any(
        issue.code == "schema-version-missing" and issue.level == "info"
        for issue in dataset.issues
    )


def test_duplicate_edges_merge_evidence(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst"), native_group(1120, "Helpdesk")],
        [
            relationship("MemberOf", sid(1105), sid(1120), detail="first record"),
            relationship("MemberOf", sid(1105), sid(1120), detail="second record"),
        ],
    )
    dataset = load_payload(tmp_path, payload)
    assert len(dataset.edges) == 1
    assert len(dataset.edges[0].evidence) == 2


def test_sid_case_is_normalised_for_objects_and_endpoints(tmp_path):
    payload = native_payload(
        [
            {
                "id": sid(1105).lower(),
                "type": "user",
                "name": "analyst",
                "sid": sid(1105).lower(),
            },
            {"id": sid(1120).lower(), "type": "group", "name": "Helpdesk"},
        ],
        [relationship("MemberOf", sid(1105).lower(), sid(1120).lower())],
    )
    dataset = load_payload(tmp_path, payload)
    assert sid(1105) in dataset.objects
    assert {(edge.source, edge.target) for edge in dataset.edges} == {(sid(1105), sid(1120))}


def test_collection_block_and_gaps_are_preserved(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst")],
        gaps=["Sessions were not collected."],
        complete=False,
    )
    dataset = load_payload(tmp_path, payload)
    assert dataset.collection.mode == "offline"
    assert dataset.collection.complete is False
    assert dataset.collection.gaps == ["Sessions were not collected."]


def test_dn_containment_is_derived_when_absent(tmp_path):
    payload = native_payload(
        [
            native_domain(),
            {
                "id": "dn:ou=staff,dc=corp,dc=example",
                "type": "ou",
                "name": "Staff",
                "dn": "OU=Staff,DC=corp,DC=example",
            },
            native_user(1105, "analyst", dn="CN=Analyst,OU=Staff,DC=corp,DC=example"),
        ]
    )
    dataset = load_payload(tmp_path, payload)
    containment = [edge for edge in dataset.edges if edge.type == "Contains"]
    assert len(containment) == 2  # domain -> OU, OU -> user
    ou_edge = next(
        edge
        for edge in containment
        if edge.target == "dn:ou=staff,dc=corp,dc=example" or edge.source.startswith("dn:")
    )
    assert ou_edge.quality.value == "derived"


def test_example_bloodhound_data_has_expected_targets(tmp_path, example_export):
    dataset = load_dataset([str(example_export)])
    result = analyse(dataset, AnalysisConfig())
    definitions = {target.definition for target in result.resolution.targets}
    assert {"Domain Admins", "krbtgt", "Domain object"} <= definitions
    assert result.search.stats.sources_found > 0

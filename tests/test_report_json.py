"""JSON report: documented schema, deterministic output, no sensitive values."""

from __future__ import annotations

import json

from adaudit import SCHEMA_VERSION
from adaudit.report import json_report

from support import (
    analyse_payload,
    native_domain,
    native_group,
    native_payload,
    native_user,
    relationship,
    sid,
)

FIXED_TIMESTAMP = "2026-01-01T00:00:00Z"


def sample(tmp_path):
    payload = native_payload(
        [
            native_user(
                1105,
                "analyst",
                attributes={"serviceprincipalnames": ["MSSQLSvc/secret-host.corp.example:1433"]},
            ),
            native_group(512, "Domain Admins"),
            native_group(1120, "Helpdesk"),
            native_domain(),
        ],
        [
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
        ],
    )
    return analyse_payload(tmp_path, payload)


def render(result, **kwargs):
    return json_report.render(result, generated_at=FIXED_TIMESTAMP, **kwargs)


def test_top_level_schema(tmp_path):
    document = json.loads(render(sample(tmp_path)))
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["tool"]["name"] == "AD-Audit"
    assert document["tool"]["version"]
    assert document["generated_at"] == FIXED_TIMESTAMP
    assert set(document) == {
        "schema_version",
        "tool",
        "generated_at",
        "assessment",
        "collection",
        "analysis",
        "summary",
        "findings",
        "privilege_paths",
        "limitations",
        "notes",
        "excluded_data",
    }


def test_assessment_and_collection_blocks(tmp_path):
    document = json.loads(render(sample(tmp_path)))
    assert document["assessment"]["target_domain"] == "corp.example"
    assert document["assessment"]["mode"] == "offline"
    assert document["assessment"]["format"] == "adaudit"
    assert document["assessment"]["complete"] is True
    assert document["collection"]["object_total"] == 4
    assert document["collection"]["objects"] == {"domain": 1, "group": 2, "user": 1}
    assert document["collection"]["relationships"] == 2
    assert document["collection"]["relationship_types"] == {"GenericAll": 1, "MemberOf": 1}


def test_analysis_block_records_configuration(tmp_path):
    result = sample(tmp_path)
    document = json.loads(render(result))
    analysis = document["analysis"]
    assert analysis["graph"]["nodes"] == 4
    assert analysis["graph"]["relationships"] == 2
    assert analysis["configuration"]["max_depth"] == 6
    assert analysis["configuration"]["include_default_targets"] is True
    assert analysis["search"]["count"] == len(result.search.paths)
    assert set(analysis["targets"][0]) == {
        "id",
        "label",
        "definition",
        "tier",
        "rationale",
        "matched_by",
        "object_type",
    }


def test_summary_matches_findings_array(tmp_path):
    document = json.loads(render(sample(tmp_path)))
    summary = document["summary"]
    assert summary["total"] == len(document["findings"])
    assert summary["high"] + summary["critical"] + summary["medium"] + summary["low"] + summary["info"] == summary["total"]


def test_findings_hide_info_unless_verbose(tmp_path):
    payload = native_payload([native_user(1105, "analyst"), native_group(512, "Domain Admins")])
    result = analyse_payload(tmp_path, payload)
    quiet = json.loads(render(result))
    verbose = json.loads(render(result, verbose=True))
    assert all(finding["severity"] != "info" for finding in quiet["findings"])
    assert any(finding["severity"] == "info" for finding in verbose["findings"])


def test_finding_fields_are_complete(tmp_path):
    document = json.loads(render(sample(tmp_path)))
    finding = next(item for item in document["findings"] if item["check_id"] == "AD-PATH")
    for key in (
        "id",
        "check_id",
        "title",
        "severity",
        "confidence",
        "category",
        "description",
        "source_objects",
        "target_objects",
        "path",
        "evidence",
        "impact",
        "recommendation",
        "limitations",
    ):
        assert key in finding
    assert finding["path"]["steps"]
    assert finding["path"]["steps"][0]["evidence"][0]["reference"]


def test_output_is_deterministic(tmp_path):
    result = sample(tmp_path)
    first = render(result)
    second = render(sample(tmp_path))
    assert first == second


def test_privilege_paths_mirror_search_results(tmp_path):
    result = sample(tmp_path)
    document = json.loads(render(result))
    assert len(document["privilege_paths"]) == len(result.search.paths)
    for path in document["privilege_paths"]:
        assert path["nodes"][0] == path["source"]
        assert path["nodes"][-1] == path["target"]


def test_object_attribute_values_are_not_exported(tmp_path):
    rendered = render(sample(tmp_path))
    assert "MSSQLSvc/secret-host" not in rendered
    assert "serviceprincipalnames" not in rendered
    document = json.loads(rendered)
    assert document["excluded_data"]


def test_limitations_and_notes_are_unique(tmp_path):
    document = json.loads(render(sample(tmp_path)))
    assert len(document["limitations"]) == len(set(document["limitations"]))
    assert len(document["notes"]) == len(set(document["notes"]))


def test_targets_without_inbound_edges_are_flagged(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()]
    )
    document = json.loads(render(analyse_payload(tmp_path, payload)))
    flagged = {item["id"] for item in document["analysis"]["targets_without_evidence"]}
    assert sid(512) in flagged
    assert all(item["reason"] for item in document["analysis"]["targets_without_evidence"])

"""Finding engine: evidence-backed findings, separated severity/confidence."""

from __future__ import annotations

from adaudit.models import Confidence, Severity

from support import (
    analyse_payload,
    native_computer,
    native_domain,
    native_group,
    native_payload,
    native_user,
    relationship,
    sid,
)


def path_findings(result):
    return [finding for finding in result.findings if finding.check_id == "AD-PATH"]


def base_objects():
    return [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()]


def test_direct_control_is_critical_and_confirmed(tmp_path):
    payload = native_payload(
        base_objects(), [relationship("GenericAll", sid(1105), sid(512))]
    )
    result = analyse_payload(tmp_path, payload)
    findings = path_findings(result)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.path is not None
    assert finding.path.length == 1
    assert finding.id.startswith("AD-PATH-")
    assert finding.source_objects == [sid(1105)]
    assert finding.target_objects == [sid(512)]
    assert finding.evidence and finding.evidence[0]["quality"] == "explicit"
    assert finding.recommendation
    assert finding.limitations


def test_direct_membership_is_high_not_critical(tmp_path):
    payload = native_payload(
        base_objects(), [relationship("MemberOf", sid(1105), sid(512))]
    )
    result = analyse_payload(tmp_path, payload)
    finding = path_findings(result)[0]
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.CONFIRMED


def test_multi_hop_path_stays_high_but_not_critical(tmp_path):
    payload = native_payload(
        base_objects()
        + [native_group(1120, "Helpdesk")],
        [
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload)
    finding = path_findings(result)[0]
    assert finding.severity is Severity.HIGH
    assert finding.path is not None and finding.path.length == 2


def test_derived_edge_lowers_confidence(tmp_path):
    payload = native_payload(
        base_objects(),
        [relationship("GenericAll", sid(1105), sid(512), quality="derived")],
    )
    result = analyse_payload(tmp_path, payload)
    finding = path_findings(result)[0]
    assert finding.confidence is Confidence.LIKELY
    assert finding.severity is Severity.HIGH  # direct control no longer CRITICAL
    assert any("derived" in limitation for limitation in finding.limitations)


def test_unresolved_intermediate_object_downgrades_to_possible(tmp_path):
    unknown = "S-1-5-21-1004336348-1177238915-682003330-9999"
    payload = native_payload(
        base_objects()
        + [
            {
                "id": unknown,
                "type": "unknown",
                "name": unknown,
                "attributes": {"unresolved": True},
            }
        ],
        [
            relationship("GenericWrite", sid(1105), unknown),
            relationship("GenericAll", unknown, sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload)
    finding = path_findings(result)[0]
    assert finding.confidence is Confidence.POSSIBLE
    assert finding.severity is Severity.MEDIUM
    assert any("weakly supported" in limitation for limitation in finding.limitations)


def test_finding_ids_are_stable_across_runs(tmp_path):
    payload = native_payload(
        base_objects()
        + [native_group(1120, "Helpdesk")],
        [
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
        ],
    )
    first = analyse_payload(tmp_path, payload)
    second = analyse_payload(tmp_path, payload)
    assert [finding.id for finding in first.findings] == [
        finding.id for finding in second.findings
    ]


def test_no_path_means_no_path_findings_but_gap_is_reported(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst"), native_group(512, "Domain Admins")]
    )
    result = analyse_payload(tmp_path, payload)
    assert path_findings(result) == []
    gap = next(
        finding for finding in result.findings if finding.check_id == "AD-DATA"
    )
    assert gap.severity is Severity.INFO
    assert gap.evidence
    assert any("No Group Policy Objects" in item["detail"] for item in gap.evidence)


def test_missing_starts_are_reported(tmp_path):
    payload = native_payload(base_objects(), [relationship("MemberOf", sid(1105), sid(512))])
    result = analyse_payload(tmp_path, payload, starts=("nosuchuser",))
    assert path_findings(result) == []
    assert any("matched no object" in note for note in result.notes)


def test_start_accepts_a_distinguished_name_with_commas(tmp_path):
    payload = native_payload(
        [
            native_user(1105, "analyst", dn="CN=Analyst,OU=Staff,DC=corp,DC=example"),
            native_group(512, "Domain Admins"),
            native_domain(),
        ],
        [relationship("MemberOf", sid(1105), sid(512))],
    )
    result = analyse_payload(
        tmp_path, payload, starts=("CN=Analyst,OU=Staff,DC=corp,DC=example",)
    )
    assert len(path_findings(result)) == 1
    assert result.search.stats.sources_found == 1


def test_privileged_start_is_excluded_from_analysis(tmp_path):
    payload = native_payload(base_objects(), [relationship("MemberOf", sid(1105), sid(512))])
    result = analyse_payload(tmp_path, payload, starts=(sid(512),))
    assert path_findings(result) == []
    assert any("themselves privileged targets" in note for note in result.notes)


def test_max_paths_per_pair_prunes_and_says_so(tmp_path):
    payload = native_payload(
        base_objects() + [native_group(1120, "Helpdesk")],
        [
            relationship("MemberOf", sid(1105), sid(512)),
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload, max_paths_per_pair=1)
    assert len(path_findings(result)) == 1
    assert any("omitted for readability" in limitation for limitation in result.limitations)
    assert result.pruned_paths == 1


def test_no_resolved_targets_skips_path_analysis(tmp_path):
    payload = native_payload(base_objects(), [relationship("MemberOf", sid(1105), sid(512))])
    result = analyse_payload(tmp_path, payload, include_default_targets=False)
    assert result.search.paths == []
    assert path_findings(result) == []
    assert any("No privileged targets were resolved" in limitation for limitation in result.limitations)


def test_duplicate_relationships_do_not_duplicate_findings(tmp_path):
    payload = native_payload(
        base_objects(),
        [
            relationship("MemberOf", sid(1105), sid(512)),
            relationship("MemberOf", sid(1105), sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload)
    assert len(path_findings(result)) == 1


def test_multiple_sources_are_analysed(tmp_path):
    payload = native_payload(
        base_objects()
        + [native_user(1106, "contractor"), native_group(1120, "Helpdesk")],
        [
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("MemberOf", sid(1106), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload)
    sources = {finding.source_objects[0] for finding in path_findings(result)}
    assert sources == {sid(1105), sid(1106)}


def test_session_exposure_path_is_explained(tmp_path):
    payload = native_payload(
        base_objects() + [native_computer(1201, "WS01")],
        [relationship("Session", sid(1201), sid(1105)), relationship("MemberOf", sid(1105), sid(512))],
    )
    result = analyse_payload(tmp_path, payload)
    finding = next(
        finding
        for finding in path_findings(result)
        if finding.source_objects == [sid(1201)]
    )
    assert "credential" in finding.impact or "credentials" in finding.description
    assert finding.category == "membership"
    assert any(step["relationship"] == "Session" for step in finding.evidence)


def test_findings_are_sorted_by_severity(tmp_path):
    payload = native_payload(
        base_objects() + [native_group(1120, "Helpdesk"), native_user(1106, "contractor")],
        [
            relationship("MemberOf", sid(1105), sid(1120)),
            relationship("GenericAll", sid(1120), sid(512)),
            relationship("GenericAll", sid(1106), sid(512)),
        ],
    )
    result = analyse_payload(tmp_path, payload)
    ranks = [finding.severity.rank for finding in result.findings]
    assert ranks == sorted(ranks, reverse=True)

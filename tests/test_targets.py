"""Target resolution: definitions only become targets when data matches them."""

from __future__ import annotations

from adaudit.targets import resolve_targets

from support import (
    DOMAIN_SID,
    load_payload,
    native_domain,
    native_group,
    native_object,
    native_payload,
    native_user,
    sid,
)


def _base_payload():
    return native_payload(
        [
            native_domain(),
            native_user(1105, "analyst", dn="CN=Analyst,OU=Staff,DC=corp,DC=example"),
            native_group(512, "Domain Admins"),
            native_group(1120, "Helpdesk"),
            native_object(sid(502), "user", "krbtgt", sid_value=sid(502)),
        ]
    )


def test_resolves_domain_relative_rids(tmp_path):
    dataset = load_payload(tmp_path, _base_payload())
    resolution = resolve_targets(dataset)
    definitions = {target.definition for target in resolution.targets}
    assert "Domain Admins" in definitions
    assert "krbtgt" in definitions
    assert "Domain object" in definitions
    for target in resolution.targets:
        if target.definition in ("Domain Admins", "krbtgt"):
            assert target.matched_by == "sid"
    assert set(resolution.ids) == {sid(512), sid(502), DOMAIN_SID}


def test_missing_defaults_are_reported_not_invented(tmp_path):
    dataset = load_payload(tmp_path, _base_payload())
    resolution = resolve_targets(dataset)
    assert "Enterprise Admins" in resolution.missing_defaults
    assert all(target.label != "Enterprise Admins" for target in resolution.targets)
    assert any("not present" in note for note in resolution.notes)


def test_name_fallback_when_export_has_no_sids(tmp_path):
    payload = native_payload(
        [
            native_object("group-dn", "group", "Domain Admins", domain="corp.example"),
            native_object("user-dn", "user", "analyst", domain="corp.example"),
        ]
    )
    dataset = load_payload(tmp_path, payload)
    resolution = resolve_targets(dataset)
    assert len(resolution.targets) == 1
    target = resolution.targets[0]
    assert target.matched_by == "name"
    assert target.definition == "Domain Admins"
    assert any("Resolved by name" in note for note in resolution.notes)


def test_cli_target_by_sid_name_and_domain_prefix(tmp_path):
    payload = _base_payload()
    payload["objects"].append(native_object(sid(1201), "computer", "FS01", sid_value=sid(1201)))
    dataset = load_payload(tmp_path, payload)

    resolution = resolve_targets(dataset, cli_targets=["FS01"])
    assert any(target.id == sid(1201) and target.tier == 0 for target in resolution.targets)

    resolution = resolve_targets(dataset, cli_targets=[sid(1201)])
    assert any(target.id == sid(1201) for target in resolution.targets)

    resolution = resolve_targets(dataset, cli_targets=[r"CORP\FS01"])
    assert any(target.id == sid(1201) for target in resolution.targets)


def test_unknown_cli_target_is_reported(tmp_path):
    dataset = load_payload(tmp_path, _base_payload())
    resolution = resolve_targets(dataset, cli_targets=["NoSuchObject"])
    assert resolution.unresolved_specs == ["NoSuchObject"]
    assert any("matched no object" in note for note in resolution.notes)


def test_no_default_targets_keeps_only_explicit_ones(tmp_path):
    dataset = load_payload(tmp_path, _base_payload())
    resolution = resolve_targets(dataset, include_defaults=False)
    assert resolution.targets == []

    resolution = resolve_targets(
        dataset, cli_targets=["Domain Admins"], include_defaults=False
    )
    assert [target.id for target in resolution.targets] == [sid(512)]
    assert resolution.targets[0].matched_by == "cli"


def test_targets_are_sorted_deterministically(tmp_path):
    dataset = load_payload(tmp_path, _base_payload())
    first = [target.id for target in resolve_targets(dataset).targets]
    second = [target.id for target in resolve_targets(dataset).targets]
    assert first == second
    assert len(first) == len(set(first))

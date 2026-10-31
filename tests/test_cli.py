"""CLI: exit codes, output routing, validation and interruption."""

from __future__ import annotations

import json

import pytest

from adaudit import cli
from adaudit.cli import main

from support import (
    native_computer,
    native_domain,
    native_group,
    native_payload,
    native_user,
    relationship,
    sid,
    write_json,
)


def run(argv, capsys=None):
    code = main(argv)
    captured = capsys.readouterr() if capsys else None
    return code, captured


def test_version_and_help_exit_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "AD-Audit 0.1.0" in capsys.readouterr().out

    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "--max-depth" in help_text
    assert "EXIT CODES" in help_text


def test_unknown_option_returns_usage_error(capsys):
    assert main(["--does-not-exist"]) == 4
    # argparse raises before writing usage; the message must still be clear.
    assert "try 'adaudit --help'" in capsys.readouterr().err


def test_missing_input_returns_usage_error(capsys):
    assert main([]) == 4
    assert "no input" in capsys.readouterr().err


def test_collect_and_input_are_mutually_exclusive(capsys, example_export):
    code = main(
        [
            "--collect",
            "--server",
            "ldaps://dc01.corp.example",
            "--base-dn",
            "DC=corp,DC=example",
            "-i",
            str(example_export),
        ]
    )
    assert code == 4
    assert "separate modes" in capsys.readouterr().err


def test_missing_file_returns_usage_error(capsys, tmp_path):
    assert main(["-i", str(tmp_path / "missing.zip")]) == 4
    assert "not found" in capsys.readouterr().err


def test_example_export_reports_high_findings(capsys, example_export):
    code, captured = run(["-i", str(example_export)], capsys)
    assert code == 2
    out = captured.out
    assert "read-only · evidence-backed · no exploitation" in out
    assert "[HIGH] AD-PATH-" in out


def test_direct_control_returns_critical_exit_code(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()],
            [relationship("GenericAll", sid(1105), sid(512))],
        ),
    )
    code, captured = run(["-i", str(path)], capsys)
    assert code == 3
    assert "Critical: 1" in captured.out


def test_low_severity_returns_exit_one(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [
                native_user(1105, "analyst"),
                native_group(548, "Account Operators"),
                native_domain(),
            ],
            [relationship("MemberOf", sid(1105), sid(548), quality="inferred")],
        ),
    )
    code, captured = run(["-i", str(path)], capsys)
    assert code == 1
    assert "[LOW] AD-PATH-" in captured.out


def test_no_findings_returns_zero(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()]
        ),
    )
    code, captured = run(["-i", str(path)], capsys)
    assert code == 0
    assert "No potential privilege paths were found" in captured.out


def test_json_stdout_is_pure_json(capsys, example_export):
    code, captured = run(["-i", str(example_export), "--json"], capsys)
    assert code == 2
    document = json.loads(captured.out)
    assert document["schema_version"] == "1.0"
    assert captured.out.startswith("{")
    assert "note:" not in captured.out


def test_json_out_writes_file_and_keeps_text(capsys, example_export, tmp_path):
    target = tmp_path / "nested" / "report.json"
    code, captured = run(["-i", str(example_export), "--json-out", str(target)], capsys)
    assert code == 2
    assert target.is_file()
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["tool"]["name"] == "AD-Audit"
    assert "AD-Audit 0.1.0 · report schema 1.0" in captured.out


def test_json_and_json_out_can_be_combined(capsys, example_export, tmp_path):
    target = tmp_path / "report.json"
    code, captured = run(
        ["-i", str(example_export), "--json", "--json-out", str(target)], capsys
    )
    assert code == 2
    stdout_document = json.loads(captured.out)
    file_document = json.loads(target.read_text(encoding="utf-8"))
    assert stdout_document["summary"] == file_document["summary"]


def test_export_native_writes_reloadable_dataset(capsys, example_export, tmp_path):
    target = tmp_path / "native.json"
    code, captured = run(["-i", str(example_export), "--export-native", str(target)], capsys)
    assert code in (0, 1, 2, 3)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["objects"]

    reloaded = run(["-i", str(target), "--json"], capsys)[1].out
    document = json.loads(reloaded)
    assert document["assessment"]["format"] == "adaudit"


def test_no_color_and_width_options(capsys, example_export):
    code, captured = run(
        ["-i", str(example_export), "--no-color", "--width", "90"], capsys
    )
    assert code == 2
    assert "\033[" not in captured.out
    for line in captured.out.splitlines():
        if "http" in line:
            continue
        assert len(line) <= 90


def test_no_banner_option(capsys, example_export):
    code, captured = run(["-i", str(example_export), "--no-banner"], capsys)
    assert code == 2
    assert "♛ DOMAIN ADMINS" not in captured.out
    assert captured.out.startswith("Target:")


def test_verbose_includes_info_findings(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()]
        ),
    )
    _, quiet = run(["-i", str(path)], capsys)
    _, verbose = run(["-i", str(path), "--verbose"], capsys)
    assert "[INFO]" not in quiet.out
    assert "[INFO] AD-DATA-001" in verbose.out


def test_no_default_targets_is_explained(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [native_user(1105, "analyst"), native_group(512, "Domain Admins"), native_domain()],
            [relationship("MemberOf", sid(1105), sid(512))],
        ),
    )
    code, captured = run(["-i", str(path), "--no-default-targets"], capsys)
    assert code == 0
    assert "No privileged targets were resolved" in captured.out


def test_unresolved_target_is_reported_on_stderr(capsys, example_export):
    code, captured = run(
        ["-i", str(example_export), "--target", "NoSuchGroup"], capsys
    )
    assert code in (0, 1, 2, 3)
    assert "NoSuchGroup" in captured.err
    assert "NoSuchGroup" not in captured.out


def test_start_limits_the_analysis(capsys, example_export):
    code, captured = run(
        ["-i", str(example_export), "--start", r"CORP.EXAMPLE\helpdesk1"], capsys
    )
    assert code in (0, 1, 2, 3)
    assert "Analysed 1 starting principal(s)" in captured.out


def test_invalid_limits_are_rejected(capsys, example_export):
    for argv in (
        ["--max-depth", "0"],
        ["--max-depth", "50"],
        ["--max-paths", "0"],
        ["--max-sources", "0"],
        ["--budget", "0"],
        ["--width", "20"],
    ):
        assert main(["-i", str(example_export)] + argv) == 4
        assert capsys.readouterr().err


def test_keyboard_interrupt_exits_130(monkeypatch, capsys, example_export):
    monkeypatch.setattr(cli, "analyse", lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert main(["-i", str(example_export)]) == 130
    assert "interrupted" in capsys.readouterr().err


def test_target_selection_by_name(capsys, tmp_path):
    path = write_json(
        tmp_path,
        native_payload(
            [
                native_user(1105, "analyst"),
                native_group(512, "Domain Admins"),
                native_computer(1201, "FS01"),
            ],
            [relationship("GenericAll", sid(1105), sid(1201))],
        ),
    )
    code, captured = run(
        ["-i", str(path), "--no-default-targets", "--target", "FS01"], capsys
    )
    assert code == 3  # direct full control over an explicitly selected target
    assert "FS01" in captured.out

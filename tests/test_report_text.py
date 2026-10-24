"""Terminal report: layout conventions, counts, verbosity and colour."""

from __future__ import annotations

from adaudit.report import text

from support import (
    analyse_payload,
    native_domain,
    native_group,
    native_payload,
    native_user,
    relationship,
    sid,
)


def example_result(tmp_path):
    payload = native_payload(
        [
            native_user(1105, "analyst"),
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


def test_banner_and_context(tmp_path):
    rendered = text.render(example_result(tmp_path))
    assert "========================================" in rendered
    assert " Active Directory Security Analysis" in rendered
    assert "Target:   corp.example" in rendered
    assert "Mode:     Offline graph analysis (adaudit)" in rendered
    assert "Objects:  Users: 1 | Groups: 2 | Domains: 1" in rendered
    assert "Graph:    4 nodes" in rendered
    assert "[+] Imported adaudit dataset" in rendered
    assert "[+] Resolved" in rendered
    assert "Coverage:" in rendered


def test_finding_block_fields(tmp_path):
    rendered = text.render(example_result(tmp_path))
    assert "[HIGH] AD-PATH-" in rendered
    assert "Check:      AD-PATH" in rendered
    assert "Category:   permission" in rendered
    assert "Confidence: CONFIRMED" in rendered
    assert "Start:" in rendered
    assert "Target:" in rendered
    assert "Path:" in rendered
    assert "-[MemberOf]->" in rendered
    assert "-[GenericAll]->" in rendered
    assert "Why:" in rendered
    assert "Evidence:" in rendered
    assert "Prerequisites:" in rendered
    assert "Recommendation:" in rendered
    assert "Limitations:" in rendered
    assert "NOTE: Findings are audit results requiring human verification" in rendered


def test_summary_matches_printed_findings(tmp_path):
    result = example_result(tmp_path)
    rendered = text.render(result)
    high_line = next(line for line in rendered.splitlines() if line.startswith("High:"))
    count = int(high_line.split(":")[1].strip())
    assert rendered.count("[HIGH] ") == count
    total_line = next(line for line in rendered.splitlines() if line.startswith("Findings:"))
    total = int(total_line.split(":")[1].strip())
    assert total == rendered.count("[HIGH] ") + rendered.count("[MEDIUM] ")


def test_info_findings_hidden_unless_verbose(tmp_path):
    payload = native_payload([native_user(1105, "analyst"), native_group(512, "Domain Admins")])
    result = analyse_payload(tmp_path, payload)
    quiet = text.render(result)
    verbose = text.render(result, verbose=True)
    assert "[INFO]" not in quiet
    assert "Re-run with --verbose to include INFO findings." in quiet
    assert "[INFO] AD-DATA-001" in verbose
    # Data-quality findings have no path but must still show their evidence.
    assert "No Group Policy Objects" in verbose


def test_no_paths_message(tmp_path):
    payload = native_payload(
        [native_user(1105, "analyst"), native_group(512, "Domain Admins")]
    )
    rendered = text.render(analyse_payload(tmp_path, payload), verbose=True)
    assert "No potential privilege paths were found in the analysed data." in rendered


def test_color_codes_only_when_requested(tmp_path):
    result = example_result(tmp_path)
    plain = text.render(result, use_color=False)
    colored = text.render(result, use_color=True)
    assert "\033[1;31m" not in plain
    assert "\033[1;31m" in colored
    assert "\033[0m" in colored


def test_lines_respect_wrap_width(tmp_path):
    result = example_result(tmp_path)
    width = 80
    rendered = text.render(result, width=width)
    for line in rendered.splitlines():
        if "http" in line:
            continue  # references are URLs and are not broken
        assert len(line) <= width, line


def test_verbose_summary_counts_info_findings(tmp_path):
    payload = native_payload([native_user(1105, "analyst"), native_group(512, "Domain Admins")])
    result = analyse_payload(tmp_path, payload)
    verbose = text.render(result, verbose=True)
    info_line = next(line for line in verbose.splitlines() if line.startswith("Info:"))
    assert int(info_line.split(":")[1].strip()) >= 1
    plain = text.render(result)
    quiet_line = next(line for line in plain.splitlines() if line.startswith("Info:"))
    assert int(quiet_line.split(":")[1].strip()) == 0


def test_terminal_output_has_no_trailing_whitespace(tmp_path):
    rendered = text.render(example_result(tmp_path))
    for line in rendered.splitlines():
        assert line == line.rstrip()

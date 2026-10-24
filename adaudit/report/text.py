"""Terminal report, following the Privesc-Audit presentation conventions.

Layout rules carried over from the reference tool:

* a ``====`` banner with a one-line title, then ``Key:   value`` context lines;
* a short ``[+] <what ran>`` progress list (informational, not decoration);
* a severity count block whose numbers match the findings printed below;
* one block per finding, sorted by severity, with aligned ``Field:`` lines;
* a closing ``NOTE:`` reminding the reader that findings are audit results.

Everything is plain text with optional ANSI colour, so the output survives
being saved, mailed, or pasted into a ticket.
"""

from __future__ import annotations

import textwrap
from typing import Dict, List, Optional, Sequence

from ..analysis import AnalysisResult
from ..models import Finding, Severity
from ..relationships import EDGE_SPECS

RESET = "\033[0m"
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;35m",  # bold magenta
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[1;33m",  # bold yellow
    Severity.LOW: "\033[1;36m",  # bold cyan
    Severity.INFO: "\033[1;37m",  # bold white
}

DEFAULT_WIDTH = 100
MAX_EVIDENCE_LINES = 12


def render(
    result: AnalysisResult,
    verbose: bool = False,
    use_color: bool = False,
    width: int = DEFAULT_WIDTH,
) -> str:
    width = max(72, width)
    lines: List[str] = []
    labels = result.labels

    _banner(lines)
    _context(lines, result, width)

    for line in _progress_lines(result):
        lines.append(f"[+] {line}")
    lines.append("")

    _coverage(lines, result)
    _finding_summary(lines, result, verbose)
    _target_summary(lines, result)

    lines.append("Potential privilege paths:")
    lines.append("")

    printed_paths = 0
    for finding in result.findings:
        if not verbose and finding.severity is Severity.INFO:
            continue
        _finding_block(lines, finding, labels, use_color, width)
        if finding.check_id == "AD-PATH":
            printed_paths += 1

    if printed_paths == 0:
        lines.append("No potential privilege paths were found in the analysed data.")
        if not verbose:
            lines.append("(Re-run with --verbose to include INFO findings.)")
        lines.append("")

    if result.limitations:
        lines.append("Limitations:")
        for limitation in result.limitations:
            lines.extend(_bullet(limitation, width, base="  "))
        lines.append("")

    lines.extend(
        _wrap(
            "Findings are audit results requiring human verification, not proof of "
            "exploitability. A nonzero exit code means findings were reported - it "
            "does not mean exploitation was attempted or confirmed.",
            indent=" " * len("NOTE: "),
            width=width,
            first_indent="NOTE: ",
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def _banner(lines: List[str]) -> None:
    lines.append("========================================")
    lines.append(" Active Directory Security Analysis")
    lines.append("========================================")
    lines.append("")


def _context(lines: List[str], result: AnalysisResult, width: int) -> None:
    dataset = result.dataset
    collection = dataset.collection

    target = collection.target_domain or "unknown"
    lines.append(f"Target:   {_truncate(target, width - 10)}")
    lines.append(f"Mode:     {_mode_label(collection.mode, collection.format)}")
    if collection.inputs:
        inputs = ", ".join(collection.inputs)
        lines.append(f"Input:    {_truncate(inputs, width - 10)}")
    if collection.collected_at:
        lines.append(f"Collected: {collection.collected_at}")
    lines.append("")

    counts = dataset.object_type_counts()
    order = (
        ("user", "Users"),
        ("group", "Groups"),
        ("computer", "Computers"),
        ("domain", "Domains"),
        ("ou", "OUs"),
        ("gpo", "GPOs"),
        ("container", "Containers"),
        ("unknown", "Unresolved"),
    )
    parts = [f"{label}: {counts[key]}" for key, label in order if counts.get(key)]
    lines.append("Objects:  " + (" | ".join(parts) if parts else "none"))
    lines.append(
        f"Graph:    {len(result.graph.nodes)} nodes | {result.graph.edge_count} relationships"
    )
    lines.append("")


def _truncate(value: str, limit: int) -> str:
    if limit < 8 or len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _mode_label(mode: str, fmt: str) -> str:
    if mode == "ldap":
        return f"Live read-only LDAP collection ({fmt})"
    return f"Offline graph analysis ({fmt})"


def _progress_lines(result: AnalysisResult) -> List[str]:
    dataset = result.dataset
    lines = [
        f"Imported {dataset.collection.format} dataset "
        f"({len(dataset.objects)} objects, {result.graph.edge_count} relationships)",
    ]
    resolution = result.resolution
    if resolution.targets:
        by_sid = sum(1 for target in resolution.targets if target.matched_by == "sid")
        by_name = sum(1 for target in resolution.targets if target.matched_by == "name")
        by_cli = sum(1 for target in resolution.targets if target.matched_by == "cli")
        detail = []
        if by_sid:
            detail.append(f"{by_sid} by SID")
        if by_name:
            detail.append(f"{by_name} by name")
        if by_cli:
            detail.append(f"{by_cli} explicit")
        lines.append(
            f"Resolved {len(resolution.targets)} privileged target(s) "
            f"({', '.join(detail)})"
        )
    else:
        lines.append("Resolved 0 privileged targets")
    lines.append(
        f"Analysed {len(result.sources)} starting principal(s) "
        f"with max depth {result.config.max_depth}"
    )
    if result.search.stats.truncated:
        lines.append("Path search truncated - see limitations")
    return lines


def _coverage(lines: List[str], result: AnalysisResult) -> None:
    dataset = result.dataset
    errors = sum(1 for issue in dataset.issues if issue.level == "error")
    warnings = sum(1 for issue in dataset.issues if issue.level == "warning")
    notes = sum(1 for issue in dataset.issues if issue.level == "info")
    gaps = list(dict.fromkeys(list(dataset.collection.gaps) + dataset.gap_statements()))
    partial = bool(errors or warnings) or bool(gaps) or not dataset.collection.complete
    lines.append(f"Coverage: {'partial' if partial else 'complete'}")
    lines.append(
        f"  Import issues: {errors} error(s), {warnings} warning(s), {notes} note(s)"
    )
    lines.append(f"  Data gaps:     {len(gaps)}")
    if result.search.stats.truncated:
        lines.append("  Path search:   truncated")
    lines.append("")


def _finding_summary(lines: List[str], result: AnalysisResult, verbose: bool) -> None:
    counts = result.severity_counts_visible(verbose)
    total = sum(counts.values())
    lines.append(f"Findings: {total}")
    lines.append(f"Critical: {counts[Severity.CRITICAL.value]}")
    lines.append(f"High:     {counts[Severity.HIGH.value]}")
    lines.append(f"Medium:   {counts[Severity.MEDIUM.value]}")
    lines.append(f"Low:      {counts[Severity.LOW.value]}")
    lines.append(f"Info:     {counts[Severity.INFO.value]}")
    lines.append("")


def _target_summary(lines: List[str], result: AnalysisResult) -> None:
    summary = result.target_member_summary()
    if not summary:
        return
    lines.append("Privileged targets:")
    width = max(len(target.label) for target, _ in summary)
    for target, members in summary:
        tier = f"tier {target.tier}"
        if target.object_type == "group":
            detail = f"{members} direct member(s)"
        else:
            detail = f"{target.object_type} object"
        lines.append(
            f"  {target.label:<{width}}  {tier:<7} {detail}  [{target.matched_by}]"
        )
    lines.append("")


def _finding_block(
    lines: List[str],
    finding: Finding,
    labels: Dict[str, str],
    use_color: bool,
    width: int,
) -> None:
    color = _SEVERITY_COLOR.get(finding.severity, "") if use_color else ""
    reset = RESET if use_color else ""
    lines.append(
        f"{color}[{finding.severity.label}]{reset} {finding.id}: {finding.title}"
    )

    fields: Sequence = (
        ("Check:", finding.check_id),
        ("Category:", finding.category),
        ("Confidence:", finding.confidence.label),
    )
    for label, value in fields:
        lines.append(f"  {label:<12}{value}")

    if finding.path is not None:
        lines.append(f"  {'Start:':<12}{labels.get(finding.path.source, finding.path.source)}")
        lines.append(f"  {'Target:':<12}{labels.get(finding.path.target, finding.path.target)}")
        lines.append("  Path:")
        lines.append(f"    {labels.get(finding.path.nodes[0], finding.path.nodes[0])}")
        for edge in finding.path.steps:
            target_label = labels.get(edge.target, edge.target)
            lines.append(f"      -[{edge.type}]-> {target_label}")

        lines.append("  Why:")
        for index, edge in enumerate(finding.path.steps, start=1):
            source_label = labels.get(edge.source, edge.source)
            target_label = labels.get(edge.target, edge.target)
            spec = EDGE_SPECS.get(edge.type)
            explanation = (
                spec.explanation.format(source=source_label, target=target_label)
                if spec
                else f"{source_label} has an unrecognised relationship to {target_label}."
            )
            prefix = f"    {index}. "
            lines.extend(_wrap(explanation, indent=" " * len(prefix), width=width, first_indent=prefix))

    lines.append("  Evidence:")
    if not finding.evidence:
        lines.append("    No direct evidence records were captured.")
    for index, item in enumerate(finding.evidence[:MAX_EVIDENCE_LINES], start=1):
        relationship = item.get("relationship")
        prefix = f"    {index}. "
        if relationship:
            head = f"{relationship}: {item.get('from')} -> {item.get('to')}"
        else:
            head = str(item.get("detail", ""))
        quality = item.get("quality")
        if quality:
            head += f"  [{quality}]"
        lines.extend(_wrap(head, indent=" " * len(prefix), width=width, first_indent=prefix))
        if item.get("detail") and relationship:
            lines.extend(
                _wrap(
                    str(item["detail"]),
                    indent="       ",
                    width=width,
                    first_indent="       ",
                )
            )
        reference = item.get("reference")
        if reference:
            lines.extend(
                _wrap(f"ref: {reference}", indent="       ", width=width, first_indent="       ")
            )
    remaining = len(finding.evidence) - MAX_EVIDENCE_LINES
    if remaining > 0:
        lines.append(f"    ... {remaining} further evidence record(s) in the JSON report.")

    if finding.prerequisites:
        lines.append("  Prerequisites:")
        for prerequisite in finding.prerequisites:
            lines.extend(_bullet(prerequisite, width))

    lines.extend(_labeled_block("Impact:", finding.impact, width))
    lines.extend(_labeled_block("Recommendation:", finding.recommendation, width))
    if finding.limitations:
        lines.append("  Limitations:")
        for limitation in finding.limitations:
            lines.extend(_bullet(limitation, width))
    if finding.references:
        lines.append("  References:")
        for reference in finding.references:
            lines.extend(_wrap(reference, indent="    ", width=width))
    lines.append("")


def _bullet(text: str, width: int, base: str = "    ") -> List[str]:
    """Render a wrapped bullet whose continuation aligns under the text."""
    first = f"{base}- "
    return _wrap(text, indent=" " * len(first), width=width, first_indent=first)


def _labeled_block(label: str, value: str, width: int) -> List[str]:
    if not value:
        return []
    prefix = f"  {label} "
    return _wrap(value, indent=" " * len(prefix), width=width, first_indent=prefix)


def _wrap(
    text: str,
    indent: str,
    width: int,
    first_indent: Optional[str] = None,
) -> List[str]:
    first = first_indent if first_indent is not None else indent
    available = max(24, width - len(indent))
    wrapped = textwrap.wrap(
        text,
        width=available,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    lines = [f"{first}{wrapped[0]}"]
    for continuation in wrapped[1:]:
        lines.append(f"{indent}{continuation}")
    return lines

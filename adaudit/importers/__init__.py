"""Offline dataset import.

Two input formats are supported and both produce the same normalised
:class:`~adaudit.models.DirectoryDataset`:

``bloodhound``
    BloodHound / SharpHound JSON, either as a ``.zip`` archive of per-type JSON
    files or as a single JSON document containing those arrays.

``adaudit``
    AD-Audit's own export (``schema_version`` 1.0), written by the LDAP
    collector or by hand. See ``docs/export-format.md``.

Live collection produces the ``adaudit`` format, so a collected assessment can
be re-analysed offline without touching the domain again.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Sequence

from ..models import DirectoryDataset
from .base import BLOODHOUND_FILE_KINDS, DatasetImportError, SUPPORTED_FORMATS
from . import bloodhound, native

__all__ = [
    "BLOODHOUND_FILE_KINDS",
    "DatasetImportError",
    "SUPPORTED_FORMATS",
    "load_dataset",
    "merge_into",
]


def load_dataset(
    paths: Sequence[str],
    fmt: str = "auto",
    verbose: bool = False,
) -> DirectoryDataset:
    """Load one or more inputs into a single merged dataset.

    ``fmt`` is ``auto``, ``bloodhound`` or ``adaudit``. Detection failures raise
    :class:`DatasetImportError` with a message naming the path and the accepted
    formats; nothing is guessed.
    """
    if not paths:
        raise DatasetImportError("no input dataset was provided")
    fmt = (fmt or "auto").lower()
    if fmt not in ("auto",) + SUPPORTED_FORMATS:
        raise DatasetImportError(
            f"unknown format '{fmt}' (expected one of: auto, {', '.join(SUPPORTED_FORMATS)})"
        )

    merged = DirectoryDataset()
    merged.collection.mode = "offline"
    formats_seen: List[str] = []
    domains_seen: List[str] = []
    collected: List[str] = []

    all_complete = True
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise DatasetImportError(f"input not found: {path}")

        selected = _detect_format(path, fmt)
        if selected == "bloodhound":
            dataset = bloodhound.load(path, verbose=verbose)
        else:
            dataset = native.load(path, verbose=verbose)

        if selected not in formats_seen:
            formats_seen.append(selected)
        merge_into(merged, dataset)
        all_complete = all_complete and dataset.collection.complete
        collected.append(str(path))
        if dataset.collection.target_domain:
            if dataset.collection.target_domain not in domains_seen:
                domains_seen.append(dataset.collection.target_domain)

    merged.collection.format = "+".join(formats_seen) if formats_seen else "unknown"
    merged.collection.inputs = collected
    merged.collection.complete = all_complete and not any(
        issue.level == "error" for issue in merged.issues
    )
    if len(domains_seen) == 1:
        merged.collection.target_domain = domains_seen[0]
    elif len(domains_seen) > 1:
        merged.collection.target_domain = ", ".join(domains_seen)
        merged.add_issue(
            "multiple-domains",
            "The input contains objects from more than one domain: " + ", ".join(domains_seen),
            level="info",
        )
    return merged


def merge_into(target: DirectoryDataset, source: DirectoryDataset) -> None:
    """Merge ``source`` into ``target``, de-duplicating objects and edges."""
    for obj in source.objects.values():
        target.merge_object(obj)
    existing = {edge.key: edge for edge in target.edges}
    for edge in source.edges:
        current = existing.get(edge.key)
        if current is None:
            target.edges.append(edge)
            existing[edge.key] = edge
        else:
            current.merge(edge)
    for issue in source.issues:
        if issue not in target.issues:
            target.issues.append(issue)
    for key, value in source.stats.items():
        target.stats[key] = target.stats.get(key, 0) + value
    for gap in source.collection.gaps:
        if gap not in target.collection.gaps:
            target.collection.gaps.append(gap)


def _detect_format(path: Path, fmt: str) -> str:
    if fmt != "auto":
        return fmt

    if path.is_dir():
        if _bloodhound_kinds_in_directory(path):
            return "bloodhound"
        raise DatasetImportError(
            f"{path}: directory does not contain a recognised BloodHound export "
            f"(expected one of: {', '.join(BLOODHOUND_FILE_KINDS)}).json"
        )

    suffix = path.suffix.lower()
    if suffix == ".zip":
        return "bloodhound"
    if suffix in (".json", ".jsonl", ""):
        payload = _read_json(path)
        if isinstance(payload, dict):
            if "objects" in payload or "relationships" in payload:
                return "adaudit"
            if any(kind in payload or any(k.lower() == kind for k in payload) for kind in BLOODHOUND_FILE_KINDS):
                return "bloodhound"
        raise DatasetImportError(
            f"{path}: JSON document is neither an AD-Audit export "
            "(needs 'objects'/'relationships') nor a BloodHound object collection"
        )
    if suffix in (".csv", ".xml", ".xlsx", ".yaml", ".yml", ".txt"):
        raise DatasetImportError(
            f"{path}: '{suffix}' files are not supported. AD-Audit reads "
            "BloodHound JSON/ZIP exports and its own JSON export."
        )
    raise DatasetImportError(
        f"{path}: unsupported input format. Supported: BloodHound JSON/ZIP and "
        "AD-Audit JSON exports."
    )


def _read_json(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise DatasetImportError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    except OSError as exc:
        raise DatasetImportError(f"{path}: cannot read file ({exc})") from exc


def _bloodhound_kinds_in_directory(path: Path) -> List[str]:
    found: List[str] = []
    for candidate in path.iterdir():
        if not candidate.is_file() or candidate.suffix.lower() != ".json":
            continue
        if bloodhound.kind_for_filename(candidate.name):
            found.append(candidate.name)
    return found

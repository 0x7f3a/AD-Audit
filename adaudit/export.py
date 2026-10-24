"""Write a normalised dataset back out as an AD-Audit native export.

This is how a live collection becomes an offline artefact, and how a BloodHound
export can be converted into AD-Audit's smaller, explicit format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from .models import DirectoryDataset


def to_payload(dataset: DirectoryDataset) -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = [
        dataset.objects[object_id].to_dict() for object_id in sorted(dataset.objects)
    ]
    relationships: List[Dict[str, Any]] = []
    for edge in sorted(dataset.edges, key=lambda item: (item.type, item.source, item.target)):
        relationships.append(
            {
                "type": edge.type,
                "source": edge.source,
                "target": edge.target,
                "inherited": edge.inherited,
                "evidence": [item.to_dict() for item in edge.evidence],
            }
        )
    collection = dataset.collection
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "domain": collection.target_domain,
        "collected_at": collection.collected_at,
        "collection": {
            "mode": collection.mode,
            "complete": collection.complete,
            "gaps": sorted(collection.gaps),
        },
        "objects": objects,
        "relationships": relationships,
    }


def write_native(dataset: DirectoryDataset, path: str) -> Path:
    destination = Path(path).expanduser()
    if destination.parent and not destination.parent.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(to_payload(dataset), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return destination

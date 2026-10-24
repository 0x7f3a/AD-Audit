"""Builders for synthetic directory datasets used across the tests."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from adaudit.analysis import AnalysisConfig, AnalysisResult, analyse
from adaudit.importers import load_dataset

#: Same SID as the shipped synthetic example so fixtures can be mixed.
DOMAIN = "corp.example"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"


def sid(rid: int) -> str:
    return f"{DOMAIN_SID}-{rid}"


# ---------------------------------------------------------------------------
# Native export format
# ---------------------------------------------------------------------------


def native_object(
    object_id: str,
    object_type: str,
    name: str,
    *,
    domain: str = DOMAIN,
    dn: Optional[str] = None,
    sid_value: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "id": object_id,
        "type": object_type,
        "name": name,
        "domain": domain,
    }
    if dn:
        payload["dn"] = dn
    if sid_value:
        payload["sid"] = sid_value
    if attributes:
        payload["attributes"] = attributes
    return payload


def native_user(rid: int, name: str, **kwargs: Any) -> Dict[str, Any]:
    return native_object(sid(rid), "user", name, sid_value=sid(rid), **kwargs)


def native_group(rid: int, name: str, **kwargs: Any) -> Dict[str, Any]:
    return native_object(sid(rid), "group", name, sid_value=sid(rid), **kwargs)


def native_computer(rid: int, name: str, **kwargs: Any) -> Dict[str, Any]:
    return native_object(sid(rid), "computer", name, sid_value=sid(rid), **kwargs)


def native_domain(name: str = DOMAIN) -> Dict[str, Any]:
    return native_object(
        DOMAIN_SID,
        "domain",
        name,
        sid_value=DOMAIN_SID,
        dn="DC=corp,DC=example",
    )


def relationship(
    edge_type: str,
    source: str,
    target: str,
    quality: str = "explicit",
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "type": edge_type,
        "source": source,
        "target": target,
        "evidence": [
            {
                "detail": detail or f"{edge_type} test relationship",
                "quality": quality,
                "reference": "synthetic",
            }
        ],
    }


def native_payload(
    objects: Sequence[Dict[str, Any]],
    relationships: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    domain: str = DOMAIN,
    complete: bool = True,
    schema_version: str = "1.0",
    gaps: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": schema_version,
        "domain": domain,
        "collected_at": "2026-01-01T00:00:00Z",
        "collection": {
            "mode": "offline",
            "complete": complete,
            "gaps": list(gaps or []),
        },
        "objects": list(objects),
        "relationships": list(relationships or []),
    }


def write_json(tmp_path: Path, payload: Any, name: str = "export.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def load_payload(tmp_path: Path, payload: Dict[str, Any]):
    return load_dataset([str(write_json(tmp_path, payload))])


def analyse_payload(
    tmp_path: Path,
    payload: Dict[str, Any],
    **config: Any,
) -> AnalysisResult:
    dataset = load_payload(tmp_path, payload)
    return analyse(dataset, AnalysisConfig(**config))


# ---------------------------------------------------------------------------
# BloodHound JSON
# ---------------------------------------------------------------------------


def bh_props(name: str, dn: str, sid_value: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "name": f"{name}@{DOMAIN.upper()}",
        "domain": DOMAIN.upper(),
        "distinguishedname": dn,
    }
    if sid_value:
        data["objectsid"] = sid_value
    data.update(extra)
    return data


def bh_user(rid: int, name: str, dn: str, **extra: Any) -> Dict[str, Any]:
    return {
        "ObjectIdentifier": sid(rid),
        "Properties": bh_props(name, dn, sid(rid), **extra),
        "Aces": [],
    }


def bh_group(
    rid: int,
    name: str,
    dn: str,
    members: Iterable[Dict[str, Any]] = (),
    aces: Iterable[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    return {
        "ObjectIdentifier": sid(rid),
        "Properties": bh_props(name, dn, sid(rid)),
        "Members": list(members),
        "Aces": list(aces),
    }


def bh_member(object_id: str, primary: bool = False) -> Dict[str, Any]:
    return {"ObjectIdentifier": object_id, "ObjectType": "User", "PrimaryGroup": primary}


def bh_ace(principal: str, right: str, inherited: bool = False) -> Dict[str, Any]:
    return {
        "PrincipalSID": principal,
        "PrincipalType": "User",
        "RightName": right,
        "IsInherited": inherited,
    }


def write_bh_export(tmp_path: Path, files: Dict[str, Any], name: str = "bh") -> Path:
    directory = tmp_path / name
    directory.mkdir(parents=True, exist_ok=True)
    for filename, records in files.items():
        (directory / filename).write_text(json.dumps(records), encoding="utf-8")
    return directory


def zip_bh_export(tmp_path: Path, files: Dict[str, Any], name: str = "bh.zip") -> Path:
    target = tmp_path / name
    with zipfile.ZipFile(target, "w") as archive:
        for filename, records in files.items():
            archive.writestr(filename, json.dumps(records))
    return target

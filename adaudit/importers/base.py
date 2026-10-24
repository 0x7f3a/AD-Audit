"""Constants and errors shared by the importers."""

from __future__ import annotations

from typing import Tuple

SUPPORTED_FORMATS: Tuple[str, ...] = ("bloodhound", "adaudit")

#: Filenames BloodHound exports use for each object class.
BLOODHOUND_FILE_KINDS: Tuple[str, ...] = (
    "users",
    "groups",
    "computers",
    "domains",
    "ous",
    "gpos",
    "containers",
)


class DatasetImportError(Exception):
    """Raised when an input cannot be interpreted as a supported dataset."""

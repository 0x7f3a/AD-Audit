"""Shared fixtures and helpers for the AD-Audit test-suite.

Every fixture is synthetic: no test contacts a domain, and no test needs the
optional ``ldap3`` dependency.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture
def example_export() -> Path:
    """The synthetic BloodHound example shipped in ``examples/``."""
    return ROOT / "examples" / "corp-example"


@pytest.fixture
def repo_root() -> Path:
    return ROOT

#!/usr/bin/env python3
"""AD-Audit launcher kept at the repository root for convenience.

The implementation lives in the ``adaudit`` package; this file only makes
``python3 main.py ...`` work without installing the project first.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adaudit.cli import main

if __name__ == "__main__":
    sys.exit(main())

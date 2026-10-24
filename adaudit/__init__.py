"""AD-Audit: read-only Active Directory privilege-path analysis.

AD-Audit models collected directory data as a typed graph, searches it for
potential privilege paths to configured targets, and reports the result as
evidence-backed findings in the terminal or as JSON.

It never modifies a directory, never contacts a domain unless an explicit
collection mode is requested, and never claims a path is exploitable -- only
that the collected data connects principals in a way worth reviewing.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: Version of the JSON report schema in :mod:`adaudit.report.json_report`.
SCHEMA_VERSION = "1.0"

TOOL_NAME = "AD-Audit"

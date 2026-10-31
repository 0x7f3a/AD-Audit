"""Command-line interface.

Conventions follow the reference project: ``--help``/``--version``, a small set
of long options, text output by default, ``--json`` for machine-readable
output, and an exit code that reflects the worst severity found so the tool can
gate a pipeline.

Exit codes
----------
0  nothing actionable was found
1  low or medium findings
2  high findings (and no critical)
3  critical findings
4  usage, input or collection error
130 interrupted by the user
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Optional, Sequence

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from .analysis import AnalysisConfig, AnalysisResult, analyse
from .export import write_native
from .importers import DatasetImportError, load_dataset
from .models import Severity
from .report import json_report, text

EXIT_OK = 0
EXIT_LOW = 1
EXIT_HIGH = 2
EXIT_CRITICAL = 3
EXIT_ERROR = 4

PROG = "adaudit"


class UsageError(Exception):
    """Raised for invalid option combinations; maps to exit code 4."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse plumbing
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description=(
            "Read-only Active Directory privilege-path analysis. Builds a typed "
            "graph from collected directory data, finds potential paths to "
            "privileged targets, and reports evidence-backed findings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES:\n"
            "  %(prog)s -i bloodhound.zip\n"
            "  %(prog)s -i export.zip --start 'CORP\\analyst' --target 'Domain Admins'\n"
            "  %(prog)s -i export.zip --json-out report.json --verbose\n"
            "  %(prog)s --collect --server ldaps://dc01.corp.example --base-dn "
            "'DC=corp,DC=example' \\\n"
            "           --bind-dn 'CN=Audit,OU=Service,DC=corp,DC=example' "
            "--password-file ~/.audit.pw\n"
            "\n"
            "EXIT CODES:\n"
            "  0 nothing actionable   1 low/medium   2 high   3 critical\n"
            "  4 usage or input error 130 interrupted\n"
            "\n"
            "Findings are audit results requiring human verification, not proof of\n"
            "exploitability. AD-Audit never modifies a directory or attempts an attack."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {__version__} (report schema {SCHEMA_VERSION})",
    )

    source = parser.add_argument_group("input")
    source.add_argument(
        "-i",
        "--input",
        "--import",
        dest="inputs",
        action="append",
        default=[],
        metavar="PATH",
        help="offline dataset: BloodHound JSON/ZIP or AD-Audit JSON export "
        "(repeatable, merged)",
    )
    source.add_argument(
        "--format",
        choices=("auto", "bloodhound", "adaudit"),
        default="auto",
        help="input format (default: auto-detect)",
    )
    source.add_argument(
        "--export-native",
        metavar="PATH",
        help="write the imported/collected dataset as an AD-Audit JSON export",
    )

    ldap = parser.add_argument_group("read-only LDAP collection")
    ldap.add_argument(
        "--collect",
        action="store_true",
        help="collect from a live domain over LDAP instead of reading a file",
    )
    ldap.add_argument("--server", metavar="URL", help="ldap:// or ldaps:// URL of a domain controller")
    ldap.add_argument("--base-dn", metavar="DN", help="search base, e.g. DC=corp,DC=example")
    ldap.add_argument("--bind-dn", metavar="DN", help="account to bind as (omit for anonymous)")
    ldap.add_argument(
        "--password-file",
        metavar="PATH",
        help="read the bind password from a file (preferred over environment)",
    )
    ldap.add_argument(
        "--password-env",
        metavar="VAR",
        default="ADAUDIT_PASSWORD",
        help="environment variable holding the bind password (default: ADAUDIT_PASSWORD)",
    )
    ldap.add_argument(
        "--ask-password",
        action="store_true",
        help="prompt for the bind password without echoing it",
    )
    ldap.add_argument("--ca-cert", metavar="PATH", help="CA bundle for TLS verification")
    ldap.add_argument(
        "--no-tls-verify",
        action="store_true",
        help="disable certificate verification (explicitly insecure)",
    )
    ldap.add_argument("--start-tls", action="store_true", help="upgrade ldap:// with StartTLS")
    ldap.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS", help="LDAP timeout")
    ldap.add_argument("--page-size", type=int, default=500, metavar="N", help="LDAP page size")
    ldap.add_argument(
        "--max-entries",
        type=int,
        default=50_000,
        metavar="N",
        help="stop collecting after N objects per class (default: 50000)",
    )

    analysis = parser.add_argument_group("analysis")
    analysis.add_argument(
        "--start",
        action="append",
        default=[],
        metavar="PRINCIPAL",
        help="starting principal: DOMAIN\\name, SID, DN or object name "
        "(repeatable; default: every non-privileged user and computer)",
    )
    analysis.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="VALUE",
        help="additional privileged target (SID, DN, name or DOMAIN\\name; repeatable)",
    )
    analysis.add_argument(
        "--no-default-targets",
        action="store_true",
        help="ignore the built-in privileged-target definitions",
    )
    analysis.add_argument(
        "--max-depth", type=int, default=6, metavar="N", help="maximum path length (default: 6)"
    )
    analysis.add_argument(
        "--max-paths", type=int, default=50, metavar="N", help="maximum paths to report (default: 50)"
    )
    analysis.add_argument(
        "--max-sources",
        type=int,
        default=500,
        metavar="N",
        help="maximum implicit starting principals (default: 500)",
    )
    analysis.add_argument(
        "--max-paths-per-pair",
        type=int,
        default=3,
        metavar="N",
        help="maximum paths kept per source/target pair (default: 3)",
    )
    analysis.add_argument(
        "--budget",
        type=int,
        default=200_000,
        metavar="N",
        help="maximum graph expansions before the search stops (default: 200000)",
    )
    analysis.add_argument(
        "--allow-container-hops",
        action="store_true",
        help="also traverse structural Contains relationships (off by default: "
        "control of a container does not by itself grant control of its members)",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="emit the JSON report on stdout")
    output.add_argument("--json-out", metavar="PATH", help="also write the JSON report to PATH")
    output.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    output.add_argument(
        "--no-banner", action="store_true", help="omit the ASCII banner (useful in CI logs)"
    )
    output.add_argument("--verbose", action="store_true", help="include INFO findings")
    output.add_argument(
        "--width", type=int, default=text.DEFAULT_WIDTH, metavar="N", help="wrap width (default: 100)"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return run(args)
    except UsageError as exc:
        _error(str(exc))
        _error(f"try '{PROG} --help' for usage")
        return EXIT_ERROR
    except DatasetImportError as exc:
        _error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error("interrupted")
        return 130
    except BrokenPipeError:  # pragma: no cover - shell piping
        return EXIT_OK


def run(args: argparse.Namespace) -> int:
    _validate(args)

    config = AnalysisConfig(
        max_depth=args.max_depth,
        max_paths=args.max_paths,
        max_sources=args.max_sources,
        max_paths_per_pair=args.max_paths_per_pair,
        budget=args.budget,
        starts=tuple(args.start),
        targets=tuple(args.target),
        include_default_targets=not args.no_default_targets,
        skip_container_hops=not args.allow_container_hops,
    )

    if args.collect:
        dataset = _collect(args)
    else:
        dataset = load_dataset(args.inputs, fmt=args.format)

    if args.export_native:
        destination = write_native(dataset, args.export_native)
        _note(f"dataset exported to {destination}")

    result = analyse(dataset, config)
    _emit(result, args)
    return _exit_code(result)


def _emit(result: AnalysisResult, args: argparse.Namespace) -> None:
    for note in result.notes:
        _note(note)

    if args.json_out:
        rendered = json_report.render(result, verbose=args.verbose)
        target = os.path.expanduser(args.json_out)
        parent = os.path.dirname(target)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        _note(f"JSON report written to {target}")

    if args.json:
        sys.stdout.write(json_report.render(result, verbose=args.verbose))
        return

    use_color = (
        sys.stdout.isatty()
        and not args.no_color
        and os.environ.get("NO_COLOR") is None
    )
    sys.stdout.write(
        text.render(
            result,
            verbose=args.verbose,
            use_color=use_color,
            width=args.width,
            show_banner=not args.no_banner,
        )
    )


def _validate(args: argparse.Namespace) -> None:
    if args.collect and args.inputs:
        raise UsageError("--collect and --input are separate modes; use one of them")
    if not args.collect and not args.inputs:
        raise UsageError(
            "no input: pass -i PATH (BloodHound JSON/ZIP or AD-Audit export) "
            "or use --collect for a live read-only collection"
        )
    if args.collect:
        if not args.server:
            raise UsageError("--collect requires --server")
        if not args.base_dn:
            raise UsageError("--collect requires --base-dn")
    if args.max_depth < 1:
        raise UsageError("--max-depth must be at least 1")
    if args.max_depth > 20:
        raise UsageError("--max-depth above 20 is not supported (search would be unbounded in practice)")
    if args.max_paths < 1:
        raise UsageError("--max-paths must be at least 1")
    if args.max_sources < 1:
        raise UsageError("--max-sources must be at least 1")
    if args.max_paths_per_pair < 1:
        raise UsageError("--max-paths-per-pair must be at least 1")
    if args.budget < 1:
        raise UsageError("--budget must be at least 1")
    if args.width < 60:
        raise UsageError("--width must be at least 60")
    if args.timeout <= 0:
        raise UsageError("--timeout must be greater than zero")
    if args.page_size < 1:
        raise UsageError("--page-size must be at least 1")
    if args.max_entries < 1:
        raise UsageError("--max-entries must be at least 1")


def _collect(args: argparse.Namespace):
    from .collection import CollectionError, LDAPSettings, collect

    password = _resolve_password(args)
    try:
        settings = LDAPSettings(
            server=args.server,
            base_dn=args.base_dn,
            bind_dn=args.bind_dn,
            password=password,
            ca_cert=args.ca_cert,
            verify_tls=not args.no_tls_verify,
            start_tls=args.start_tls,
            timeout=args.timeout,
            page_size=args.page_size,
            max_entries=args.max_entries,
        )
        return collect(settings, progress=_note)
    except CollectionError as exc:
        raise UsageError(str(exc)) from exc


def _resolve_password(args: argparse.Namespace) -> Optional[str]:
    if args.password_file:
        path = os.path.expanduser(args.password_file)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as exc:
            raise UsageError(f"cannot read --password-file {path}: {exc}") from exc
        if not value:
            raise UsageError(f"--password-file {path} is empty")
        return value
    value = os.environ.get(args.password_env or "ADAUDIT_PASSWORD")
    if value:
        return value
    if args.ask_password:
        return getpass.getpass("LDAP bind password: ")
    if args.bind_dn:
        raise UsageError(
            "a bind password is required for --bind-dn: use --password-file, "
            "--password-env (default ADAUDIT_PASSWORD) or --ask-password"
        )
    return None


def _exit_code(result: AnalysisResult) -> int:
    actionable = [finding for finding in result.findings if finding.severity is not Severity.INFO]
    if not actionable:
        return EXIT_OK
    worst = max(finding.severity.rank for finding in actionable)
    if worst >= Severity.CRITICAL.rank:
        return EXIT_CRITICAL
    if worst >= Severity.HIGH.rank:
        return EXIT_HIGH
    return EXIT_LOW


def _error(message: str) -> None:
    sys.stderr.write(f"{PROG}: {message}\n")


def _note(message: str) -> None:
    sys.stderr.write(f"{PROG}: {message}\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

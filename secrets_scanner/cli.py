"""
Command line interface.

Exit codes: 0 no findings · 1 findings (after filters and baseline) · 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

from . import SEVERITY_ORDER, __version__
from .baseline import apply_baseline, load_baseline, write_baseline
from .file_scanner import DEFAULT_MAX_FILE_SIZE, ScanStats, scan_directory, scan_file
from .git_scanner import scan_git_history, scan_staged
from .ignore import IgnoreMatcher
from .report import (filter_by_severity, render_json, render_sarif, render_terminal, use_color)
from .rules import RULES


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secrets-scanner",
        description="Find hard-coded secrets in files, directories, staged changes and Git history.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  secrets-scanner --dir .\n"
            "  secrets-scanner --dir . --git --max-commits 500\n"
            "  secrets-scanner --staged                      # pre-commit hook\n"
            "  secrets-scanner --dir . --output sarif --output-file results.sarif\n"
            "  secrets-scanner --dir . --update-baseline .secrets-baseline.json\n"
            "  secrets-scanner --dir . --baseline .secrets-baseline.json\n\n"
            "Silence a finding on one line with a comment:  # secrets-scanner:ignore [SS014,...]\n"
            "Exit codes: 0 clean, 1 findings, 2 error."
        ),
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--file", "-f", metavar="PATH", help="scan a single file")
    src.add_argument("--dir", "-d", metavar="DIR", help="scan a directory recursively")
    src.add_argument("--staged", action="store_true", help="scan only what is staged in git (pre-commit)")
    p.add_argument("--git", action="store_true", help="also scan git history (needs --dir)")
    p.add_argument("--max-commits", type=int, default=100, metavar="N",
                   help="commits to scan with --git, 0 for all (default: 100)")
    p.add_argument("--output", "-o", choices=["terminal", "json", "sarif"], default="terminal")
    p.add_argument("--output-file", metavar="PATH", help="write the report to a file instead of stdout")
    p.add_argument("--severity", "-s", choices=list(SEVERITY_ORDER), metavar="LEVEL",
                   help="minimum severity to report and to fail on (CRITICAL, HIGH, MEDIUM, LOW)")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="path pattern to skip, repeatable (same syntax as .secretsignore)")
    p.add_argument("--ignore-file", metavar="PATH",
                   help="ignore file (default: .secretsignore in the scanned directory)")
    p.add_argument("--baseline", metavar="PATH", help="accept findings listed in this baseline")
    p.add_argument("--update-baseline", metavar="PATH", help="write current findings to a baseline and exit 0")
    p.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE, metavar="BYTES",
                   help=f"skip files larger than this (default: {DEFAULT_MAX_FILE_SIZE})")
    p.add_argument("--exit-zero", action="store_true", help="always exit 0, even with findings")
    p.add_argument("--no-color", action="store_true", help="disable colors (also honours NO_COLOR)")
    p.add_argument("--list-rules", action="store_true", help="list the detection rules and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _die(msg: str, code: int = 2) -> "NoReturn":  # noqa: F821
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.id}  {r.severity:<8}  {r.name}")
        sys.exit(0)
    if not (args.file or args.dir or args.staged):
        parser.error("one of --file, --dir or --staged is required")
    if args.git and not args.dir:
        parser.error("--git requires --dir")

    root = args.dir or "."
    ignore_path = args.ignore_file or os.path.join(root if os.path.isdir(root) else ".", ".secretsignore")
    ignore = IgnoreMatcher.from_file(ignore_path).extend(args.exclude)

    stats = ScanStats()
    findings = []
    try:
        if args.file:
            label = args.file
            findings += scan_file(args.file, max_file_size=args.max_file_size, stats=stats)
        elif args.dir:
            label = args.dir
            findings += scan_directory(args.dir, ignore=ignore, max_file_size=args.max_file_size, stats=stats)
            if args.git:
                print(f"[INFO] Scanning git history ({args.max_commits or 'all'} commits)...", file=sys.stderr)
                present = {(f.fingerprint, f.file_path) for f in findings}
                findings += [h for h in scan_git_history(args.dir, args.max_commits, ignore)
                             if (h.fingerprint, h.file_path) not in present]
        else:
            label = "staged changes"
            findings += scan_staged(".", ignore)
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as exc:
        _die(str(exc))

    if args.update_baseline:
        n = write_baseline(args.update_baseline, findings)
        print(f"Baseline written to {args.update_baseline} ({n} finding(s) accepted).", file=sys.stderr)
        sys.exit(0)

    if args.baseline:
        try:
            findings = apply_baseline(findings, load_baseline(args.baseline))
        except (OSError, ValueError, KeyError) as exc:
            _die(f"cannot read baseline: {exc}")

    findings = filter_by_severity(findings, args.severity)
    scanned = None if args.staged else stats.files_scanned

    if args.output == "json":
        text = render_json(findings, label, scanned, stats.skipped)
    elif args.output == "sarif":
        text = render_sarif(findings)
    else:
        color = use_color(force_off=args.no_color or bool(args.output_file))
        text = render_terminal(findings, label, scanned, stats.skipped, color)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")

    sys.exit(0 if args.exit_zero or not findings else 1)


if __name__ == "__main__":
    main()

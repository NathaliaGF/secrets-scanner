#!/usr/bin/env python3
"""
secrets-scanner — CLI entry point.

Usage:
    python main.py --dir ./my-project
    python main.py --file .env
    python main.py --dir . --git
    python main.py --dir . --output json --severity HIGH
"""

import argparse
import os
import sys

from scanner.file_scanner import scan_directory, scan_file
from scanner.git_scanner  import scan_git_history, is_git_repo
from scanner.report       import print_report, export_json


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets-scanner",
        description="Detecta segredos e credenciais expostos em código-fonte.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python main.py --file .env\n"
            "  python main.py --dir ./my-project\n"
            "  python main.py --dir . --git\n"
            "  python main.py --dir . --output json > relatorio.json\n"
            "  python main.py --dir . --severity HIGH\n"
        ),
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", "-f", metavar="PATH",
                        help="Arquivo único para escanear.")
    source.add_argument("--dir",  "-d", metavar="DIR",
                        help="Diretório para escanear recursivamente.")

    parser.add_argument("--git", action="store_true",
                        help="Também escanear histórico de commits git (requer --dir).")
    parser.add_argument("--max-commits", type=int, default=100, metavar="N",
                        help="Máximo de commits para escanear no histórico (padrão: 100).")
    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json"],
        default="terminal",
        help="Formato de saída (padrão: terminal).",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        metavar="LEVEL",
        help="Exibir apenas achados neste nível de severidade.",
    )
    return parser


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.git and not args.dir:
        parser.error("--git requer --dir para especificar o repositório.")

    all_findings = []

    # ── File scan ─────────────────────────────────────────────────────────────
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[ERRO] Arquivo não encontrado: {args.file}", file=sys.stderr)
            sys.exit(2)
        try:
            findings = scan_file(args.file)
        except Exception as exc:
            print(f"[ERRO] {exc}", file=sys.stderr)
            sys.exit(2)
        all_findings.extend(findings)
        label = args.file

    # ── Directory scan ────────────────────────────────────────────────────────
    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"[ERRO] Diretório não encontrado: {args.dir}", file=sys.stderr)
            sys.exit(2)
        try:
            findings = scan_directory(args.dir)
        except Exception as exc:
            print(f"[ERRO] {exc}", file=sys.stderr)
            sys.exit(2)
        all_findings.extend(findings)
        label = args.dir

        # ── Git history scan (optional) ───────────────────────────────────────
        if args.git:
            if not is_git_repo(args.dir):
                print(f"[AVISO] '{args.dir}' não é um repositório git. Pulando scan de histórico.",
                      file=sys.stderr)
            else:
                print(f"[INFO] Escaneando histórico git (últimos {args.max_commits} commits)…",
                      file=sys.stderr)
                try:
                    git_findings = scan_git_history(args.dir, max_commits=args.max_commits)
                    all_findings.extend(git_findings)
                except RuntimeError as exc:
                    print(f"[AVISO] {exc}", file=sys.stderr)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.output == "json":
        print(export_json(all_findings, args.severity, label))
    else:
        print_report(all_findings, args.severity, label)

    # Exit 1 when secrets found (useful for CI pipelines)
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()

"""
Render secret findings as a coloured terminal report or as JSON.
"""

import json
from typing import Optional

from . import Finding

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _C = {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.CYAN,
    }
    _RESET = Style.RESET_ALL
    _BOLD  = Style.BRIGHT
except ImportError:
    _C = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[96m",
    }
    _RESET = "\033[0m"
    _BOLD  = "\033[1m"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

_RISK_LABEL = {
    "CRITICAL": "⚠️  CRÍTICO",
    "HIGH":     "🔴 ALTO",
    "MEDIUM":   "🟡 MÉDIO",
    "LOW":      "🔵 BAIXO",
    None:       "✅ SEGURO",
}


# ── Public API ────────────────────────────────────────────────────────────────

def risk_level(findings: list[Finding]) -> Optional[str]:
    """Return the worst severity present, or None if no findings."""
    if not findings:
        return None
    order = _SEVERITY_ORDER
    return min(findings, key=lambda f: order.get(f.severity, 99)).severity


def print_report(
    findings: list[Finding],
    severity_filter: Optional[str] = None,
    label: str = "",
) -> None:
    """Print a coloured terminal report."""
    displayed = _filter_and_sort(findings, severity_filter)
    summary   = _summarise(findings)
    level     = risk_level(findings)

    _banner()
    if label:
        print(f"\n🔍 Escopo: {label}")
    print("─" * 60)

    if not displayed:
        print("\n✅  Nenhum segredo encontrado para os filtros selecionados.\n")
    else:
        # Group by file for readability
        by_file: dict[str, list[Finding]] = {}
        for f in displayed:
            by_file.setdefault(f.file_path, []).append(f)

        for file_path, file_findings in by_file.items():
            commit_info = ""
            if file_findings[0].commit:
                commit_info = f"  (commit {file_findings[0].commit})"
            print(f"\n📄 {file_path}{commit_info}")

            for f in file_findings:
                _print_finding(f)

    print("─" * 60)
    total = len(findings)
    c = summary.get("CRITICAL", 0)
    h = summary.get("HIGH", 0)
    m = summary.get("MEDIUM", 0)
    lo = summary.get("LOW", 0)
    print(
        f"RESUMO: {total} achado{'s' if total != 1 else ''}  |  "
        f"🔴 CRITICAL: {c}  |  🔴 HIGH: {h}  |  🟡 MEDIUM: {m}  |  🔵 LOW: {lo}"
    )
    print(f"Nível de risco: {_RISK_LABEL.get(level, '—')}")
    print("─" * 60)
    print()


def export_json(
    findings: list[Finding],
    severity_filter: Optional[str] = None,
    label: str = "",
) -> str:
    """Return the scan report as a JSON string."""
    displayed = _filter_and_sort(findings, severity_filter)
    summary   = _summarise(findings)
    level     = risk_level(findings)

    findings_data = []
    for f in displayed:
        entry: dict = {
            "id":             f.rule_id,
            "severity":       f.severity,
            "name":           f.name,
            "file":           f.file_path,
            "line":           f.line,
            "line_content":   f.line_content,
            "secret_preview": f.secret_preview,
            "detail":         f.detail,
            "fix":            f.fix,
        }
        if f.commit:
            entry["commit"]         = f.commit
            entry["commit_message"] = f.commit_message
        findings_data.append(entry)

    return json.dumps(
        {
            "scope":          label,
            "risk_level":     level or "NONE",
            "total_findings": len(findings),
            "findings":       findings_data,
            "summary":        summary,
        },
        indent=2,
        ensure_ascii=False,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _filter_and_sort(
    findings: list[Finding],
    severity_filter: Optional[str],
) -> list[Finding]:
    if severity_filter:
        findings = [f for f in findings if f.severity == severity_filter.upper()]
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line))


def _summarise(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _coloured(text: str, severity: str) -> str:
    return f"{_C.get(severity, '')}{text}{_RESET}"


def _banner() -> None:
    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║              SECRETS SCANNER — RELATÓRIO                   ║")
    print("╚════════════════════════════════════════════════════════════╝")


def _print_finding(f: Finding) -> None:
    icon  = _ICONS.get(f.severity, "⚪")
    label = _coloured(f"[{f.severity:<8}]", f.severity)
    print(f"  {icon} {label} {f.rule_id} — {f.name}")
    print(f"             Linha:   {f.line}")
    print(f"             Código:  {f.line_content.strip()}")
    print(f"             Segredo: {f.secret_preview}")
    print(f"             Detalhe: {f.detail}")
    print(f"             Fix:     {f.fix}")
    print()

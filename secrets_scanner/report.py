"""
Render findings as a terminal report, JSON or SARIF 2.1.0.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

from . import SEVERITY_ORDER, Finding, __version__
from .rules import RULES

_INFO_URI = "https://github.com/NathaliaGF/secrets-scanner"

_ANSI = {"CRITICAL": "\033[91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}
_RESET, _BOLD = "\033[0m", "\033[1m"
_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

# GitHub Code Scanning uses security-severity to rank alerts (0-10).
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def use_color(stream=None, force_off: bool = False) -> bool:
    stream = stream or sys.stdout
    if force_off or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def risk_level(findings: list[Finding]) -> Optional[str]:
    if not findings:
        return None
    return min(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)).severity


def filter_by_severity(findings: list[Finding], minimum: Optional[str]) -> list[Finding]:
    """Keep findings at *minimum* severity or worse."""
    if not minimum:
        return findings
    limit = SEVERITY_ORDER[minimum.upper()]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= limit]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line, f.rule_id))


def summarise(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


# ── Terminal ──────────────────────────────────────────────────────────────────

def render_terminal(findings: list[Finding], label: str = "", files_scanned: Optional[int] = None,
                    skipped: Optional[list] = None, color: bool = False) -> str:
    def paint(text: str, sev: str) -> str:
        return f"{_ANSI.get(sev, '')}{text}{_RESET}" if color else text

    bold = (lambda t: f"{_BOLD}{t}{_RESET}") if color else (lambda t: t)
    out: list[str] = [bold(f"secrets-scanner {__version__}")]
    if label:
        out.append(f"Scope: {label}")
    if files_scanned is not None:
        out.append(f"Files scanned: {files_scanned}")
    out.append("─" * 64)

    if not findings:
        out.append("\n✅  No secrets found.\n")
    else:
        by_file: dict[str, list[Finding]] = {}
        for f in _sorted(findings):
            by_file.setdefault(f.file_path, []).append(f)
        for path, items in by_file.items():
            out.append(f"\n📄 {bold(path)}")
            for f in items:
                where = f"line {f.line}"
                if f.commit:
                    where += f", commit {f.commit}"
                    if f.commit_message and f.commit != "staged":
                        where += f" ({f.commit_message[:50]})"
                out.append(f"  {_ICONS.get(f.severity, '⚪')} {paint(f'[{f.severity}]', f.severity)} "
                           f"{f.rule_id} {f.name}  ({where})")
                out.append(f"     Code:   {f.line_content}")
                out.append(f"     Secret: {f.secret_preview}")
                out.append(f"     Fix:    {f.fix}")

    if skipped:
        out.append("")
        out.append(f"⚠️  {len(skipped)} file(s) were not scanned:")
        for path, reason in skipped[:10]:
            out.append(f"   - {path}: {reason}")
        if len(skipped) > 10:
            out.append(f"   ... and {len(skipped) - 10} more")

    s = summarise(findings)
    level = risk_level(findings)
    out.append("─" * 64)
    out.append(f"{len(findings)} finding(s): CRITICAL {s['CRITICAL']} · HIGH {s['HIGH']} · "
               f"MEDIUM {s['MEDIUM']} · LOW {s['LOW']}")
    out.append(f"Risk level: {level or 'NONE'}")
    return "\n".join(out) + "\n"


# ── JSON ──────────────────────────────────────────────────────────────────────

def render_json(findings: list[Finding], label: str = "", files_scanned: Optional[int] = None,
                skipped: Optional[list] = None) -> str:
    items = []
    for f in _sorted(findings):
        entry = {
            "rule_id": f.rule_id, "severity": f.severity, "name": f.name,
            "file": f.file_path, "line": f.line, "line_content": f.line_content,
            "secret_preview": f.secret_preview, "fingerprint": f.fingerprint,
            "detail": f.detail, "fix": f.fix,
        }
        if f.commit:
            entry["commit"] = f.commit
            entry["commit_message"] = f.commit_message
        items.append(entry)
    return json.dumps({
        "tool": {"name": "secrets-scanner", "version": __version__},
        "scope": label,
        "summary": {
            "files_scanned": files_scanned,
            "files_skipped": len(skipped or []),
            "total_findings": len(findings),
            "risk_level": risk_level(findings) or "NONE",
            "by_severity": summarise(findings),
        },
        "findings": items,
    }, indent=2, ensure_ascii=False)


# ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────

def render_sarif(findings: list[Finding]) -> str:
    rules = [{
        "id": r.id,
        "name": r.name,
        "shortDescription": {"text": r.name},
        "fullDescription": {"text": r.detail},
        "help": {"text": f"{r.detail}\n\nFix: {r.fix}"},
        "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
        "properties": {"tags": ["security", "secret"], "security-severity": _SECURITY_SEVERITY[r.severity]},
    } for r in RULES]
    index = {r.id: i for i, r in enumerate(RULES)}

    results = []
    for f in _sorted(findings):
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.name} detected ({f.secret_preview}). {f.fix}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file_path.replace(os.sep, "/")},
                "region": {"startLine": max(f.line, 1)},
            }}],
            "partialFingerprints": {"secretFingerprint/v1": f.fingerprint},
        }
        if f.commit:
            result["properties"] = {"commit": f.commit}
        results.append(result)

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secrets-scanner", "version": __version__,
                "informationUri": _INFO_URI, "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)

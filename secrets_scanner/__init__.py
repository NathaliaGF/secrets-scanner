"""secrets-scanner: find hard-coded secrets in files, directories, staged changes and Git history."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

__version__ = "1.0.0"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def fingerprint(rule_id: str, secret: str) -> str:
    """Stable id of a finding. It never stores the secret: only a truncated SHA-256."""
    return hashlib.sha256(f"{rule_id}:{secret}".encode("utf-8", "ignore")).hexdigest()[:20]


@dataclass
class Finding:
    """A single secret detected by a rule."""

    rule_id: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    name: str
    file_path: str          # relative to the scanned directory when scanning a directory
    line: int               # 1-based
    line_content: str       # the line with every detected secret masked
    secret_preview: str     # e.g. "AKIA...MPLE"
    detail: str
    fix: str
    fingerprint: str = ""
    commit: Optional[str] = None          # short SHA, or "staged" (history / staged scans)
    commit_message: Optional[str] = None

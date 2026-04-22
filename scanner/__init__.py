from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """A single secret detected by a scanner rule."""

    rule_id: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    name: str
    file_path: str
    line: int               # 1-based
    line_content: str       # line with secret masked
    secret_preview: str     # e.g. "sk_live_51H4...5678"
    detail: str
    fix: str
    commit: Optional[str] = None          # git SHA (git-history scan only)
    commit_message: Optional[str] = None

"""
Ways to silence findings:

* ``.secretsignore`` / ``--exclude``: path patterns (gitignore-lite, no negation).
* inline comment ``secrets-scanner:ignore`` or ``secrets-scanner:ignore SS014,SS015``.
* baseline file (see baseline.py).
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Iterable, Optional

_INLINE_RE = re.compile(r"secrets?-?scanner\s*:\s*ignore\b(?P<rest>[^\r\n]*)", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"\bSS\d{3}\b", re.IGNORECASE)


def inline_ignored_rules(line: str) -> Optional[set[str]]:
    """None: no ignore comment. Empty set: ignore everything on the line. Else: those rule ids."""
    m = _INLINE_RE.search(line)
    if not m:
        return None
    return {r.upper() for r in _RULE_ID_RE.findall(m.group("rest"))}


class IgnoreMatcher:
    """Matches relative POSIX paths against ignore patterns."""

    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns = [p.strip() for p in patterns if p.strip() and not p.strip().startswith("#")]

    @classmethod
    def from_file(cls, path: str) -> "IgnoreMatcher":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls(fh.read().splitlines())
        except FileNotFoundError:
            return cls()

    def extend(self, patterns: Iterable[str]) -> "IgnoreMatcher":
        return IgnoreMatcher([*self.patterns, *patterns])

    def matches(self, rel_path: str, is_dir: bool = False) -> bool:
        rel = rel_path.replace(os.sep, "/")
        if rel.startswith("./"):
            rel = rel[2:]
        if rel in ("", "."):
            return False
        return any(self._match(pat, rel, is_dir) for pat in self.patterns)

    @staticmethod
    def _match(pat: str, rel: str, is_dir: bool) -> bool:
        dir_only = pat.endswith("/")
        pat = pat.strip("/")
        if not pat:
            return False
        anchored = "/" in pat                      # a slash anchors the pattern to the scan root
        segments = rel.split("/")
        for k in range(1, len(segments) + 1):      # the path itself and each parent directory
            is_last = k == len(segments)
            candidate = "/".join(segments[:k]) if anchored else segments[k - 1]
            if fnmatch.fnmatch(candidate, pat) and (not is_last or not dir_only or is_dir):
                return True
        return False

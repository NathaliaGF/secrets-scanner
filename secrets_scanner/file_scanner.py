"""
Line-level detection engine plus file and directory scanning.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from . import SEVERITY_ORDER, Finding, fingerprint
from .ignore import IgnoreMatcher, inline_ignored_rules
from .rules import RULES, Rule

DEFAULT_MAX_FILE_SIZE = 1_000_000  # bytes

_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "Gemfile.lock", "composer.lock",
    "poetry.lock", "Pipfile.lock", "pnpm-lock.yaml", "Cargo.lock", "go.sum",
}

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "vendor", "bower_components", ".terraform", ".eggs",
}

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".mov", ".avi", ".mkv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".lock", ".map",
}

_MAX_LINE_LEN = 2000  # longer lines are minified / generated

# Words that mark a value as "not a real secret" when they appear as a whole token.
_PLACEHOLDER_TOKENS = {
    "your", "yours", "example", "examples", "placeholder", "changeme", "replace", "replaceme",
    "insert", "dummy", "fake", "mock", "sample", "todo", "fixme", "redacted", "xxx", "xxxx",
    "here", "null", "none", "undefined",
}
# Words that, as the whole value, are type names / keywords rather than secrets.
_NON_SECRET_WORDS = {
    "password", "passwd", "secret", "token", "string", "str", "required", "optional",
    "hidden", "prompt", "ask", "true", "false", "nullable", "secure", "encrypted",
}

_CODE_EXPR_RES = (
    re.compile(r"^[A-Za-z_][\w.]*\("),            # function call: get_password(
    re.compile(r"^[A-Za-z_][\w.]*\["),            # indexing: request.form[
    re.compile(r"\$\{|\{\{|%\(|\$\("),            # ${VAR}, {{ var }}, %(var)s, $(cmd)
    re.compile(r"^<[^>]+>$"),                     # <your-password>
    re.compile(r"^\$\w+$"),                       # $DB_PASS
    re.compile(r"^(?:os\.environ|process\.env|getenv|ENV\[)"),
)
_MASKED_RE = re.compile(r"^\S{2,4}\.\.\.\S{4}$|^\S{2}\*{4}$")   # our own _mask() output
_PATH_OR_URL_RE = re.compile(r"^(?:[./~]|[A-Za-z]:\\|https?://)")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z_.]*$")


@dataclass
class Hit:
    rule: Rule
    secret: str
    start: int
    end: int

    @property
    def preview(self) -> str:
        return _mask(self.secret) if self.rule.mask else self.secret


@dataclass
class ScanStats:
    files_scanned: int = 0
    skipped: list = field(default_factory=list)   # (path, reason)


# ── Helpers kept importable for tests ─────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _mask(secret: str) -> str:
    """Show only the first and last 4 characters of a secret."""
    if len(secret) <= 10:
        return secret[:2] + "****"
    return secret[:4] + "..." + secret[-4:]


def _is_placeholder(value: str) -> bool:
    """True if the value looks like a placeholder or code expression rather than a real secret."""
    v = value.strip()
    if _MASKED_RE.match(v):                      # already masked by this tool (pasted report)
        return True
    if any(r.search(v) for r in _CODE_EXPR_RES):
        return True
    tokens = [t for t in re.split(r"[^a-z0-9]+", v.lower()) if t]
    if any(t in _PLACEHOLDER_TOKENS for t in tokens):
        return True
    if len(tokens) == 1 and tokens[0] in _NON_SECRET_WORDS:
        return True
    if re.fullmatch(r"[xX*.\-_0]+", v):
        return True
    if len(set(v.lower().replace("-", "").replace("_", ""))) < 3:
        return True
    return False


def _is_binary(path: str) -> bool:
    """True if the first 8 KB contain a null byte (or the file cannot be opened)."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


def _should_skip_file(fname: str) -> bool:
    base = os.path.basename(fname)
    lower = base.lower()
    if base in _SKIP_FILENAMES or lower in {n.lower() for n in _SKIP_FILENAMES}:
        return True
    if lower.endswith((".min.js", ".min.css")):
        return True
    return os.path.splitext(lower)[1] in _SKIP_EXTENSIONS


# ── Detection ─────────────────────────────────────────────────────────────────

def _accept(rule: Rule, line: str, match: re.Match) -> Optional[Hit]:
    """Apply the filters of *rule* to a regex match. Returns a Hit or None."""
    g = rule.secret_group
    raw = match.group(g)
    if raw is None:
        return None
    start, end = match.start(g), match.end(g)
    secret = raw.strip("'\"` \t")
    if len(secret) < rule.min_len:
        return None
    if rule.generic:
        quoted = start > 0 and line[start - 1] in "\"'"
        if _is_placeholder(secret):
            return None
        if not quoted and (_PATH_OR_URL_RE.match(secret) or _IDENTIFIER_RE.match(secret) and ("_" in secret or "." in secret)):
            return None
        if rule.min_entropy and _entropy(secret) < rule.min_entropy:
            return None
    return Hit(rule, secret, start, end)


def _match_rule(line: str, rule: Rule) -> list[Hit]:
    hits = []
    for m in rule.pattern.finditer(line):
        hit = _accept(rule, line, m)
        if hit:
            hits.append(hit)
    return hits


def _check_line(line: str, rule: Rule) -> Optional[tuple[str, str]]:
    """Return (secret, masked_line) if *rule* fires on *line*, else None."""
    hits = _match_rule(line, rule)
    if not hits:
        return None
    return hits[0].secret, mask_line(line, hits)


def mask_line(line: str, hits: list[Hit]) -> str:
    """Replace every detected secret in *line* by its masked preview."""
    out = line
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        out = out[: h.start] + h.preview + out[h.end:]
    return out


def find_secrets(line: str) -> list[Hit]:
    """All secrets in a line. Overlapping hits are resolved: specific rules beat generic ones."""
    ignored = inline_ignored_rules(line)
    if ignored is not None and not ignored:        # bare "secrets-scanner:ignore"
        return []
    hits: list[Hit] = []
    for rule in RULES:
        hits.extend(h for h in _match_rule(line, rule) if not (ignored and rule.id in ignored))
    hits.sort(key=lambda h: (h.rule.generic, SEVERITY_ORDER[h.rule.severity], h.start))
    accepted: list[Hit] = []
    for h in hits:
        if all(h.end <= a.start or h.start >= a.end for a in accepted):
            accepted.append(h)
    return sorted(accepted, key=lambda h: h.start)


def findings_for_line(line: str, file_path: str, lineno: int, **extra) -> list[Finding]:
    hits = find_secrets(line)
    if not hits:
        return []
    masked = mask_line(line, hits).strip()
    return [
        Finding(
            rule_id=h.rule.id, severity=h.rule.severity, name=h.rule.name,
            file_path=file_path, line=lineno, line_content=masked,
            secret_preview=h.preview, detail=h.rule.detail, fix=h.rule.fix,
            fingerprint=fingerprint(h.rule.id, h.secret), **extra,
        )
        for h in hits
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def scan_file(
    file_path: str,
    *,
    display_path: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    stats: Optional[ScanStats] = None,
) -> list[Finding]:
    """Scan a single text file.

    Raises FileNotFoundError if it does not exist. Unreadable, binary and oversized files are
    skipped and recorded in *stats*.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    shown = display_path or file_path

    def skip(reason: str) -> list[Finding]:
        if stats is not None:
            stats.skipped.append((shown, reason))
        return []

    try:
        if os.path.getsize(file_path) > max_file_size:
            return skip(f"larger than {max_file_size} bytes")
    except OSError as exc:
        return skip(f"unreadable ({exc.strerror})")
    if _is_binary(file_path):
        return skip("binary")

    findings: list[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, raw in enumerate(fh, start=1):
                if len(raw) > _MAX_LINE_LEN:
                    continue
                findings.extend(findings_for_line(raw.rstrip("\r\n"), shown, lineno))
    except OSError as exc:
        return skip(f"unreadable ({exc.strerror})")
    if stats is not None:
        stats.files_scanned += 1
    return findings


def scan_directory(
    directory: str,
    *,
    ignore: Optional[IgnoreMatcher] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    stats: Optional[ScanStats] = None,
) -> list[Finding]:
    """Recursively scan *directory*. Paths in the findings are relative to it."""
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Directory not found: {directory}")

    findings: list[Finding] = []
    for root, dirs, files in os.walk(directory):
        rel_root = os.path.relpath(root, directory)
        dirs[:] = sorted(
            d for d in dirs
            if d not in _SKIP_DIRS
            and not (ignore and ignore.matches(_join(rel_root, d), is_dir=True))
        )
        for fname in sorted(files):
            if _should_skip_file(fname):
                continue
            rel = _join(rel_root, fname)
            if ignore and ignore.matches(rel):
                continue
            findings.extend(
                scan_file(os.path.join(root, fname), display_path=rel,
                          max_file_size=max_file_size, stats=stats)
            )
    return findings


def _join(rel_root: str, name: str) -> str:
    return name if rel_root in (".", "") else f"{rel_root}/{name}".replace(os.sep, "/")

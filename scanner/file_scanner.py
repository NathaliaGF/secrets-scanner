"""
Scans files and directories for exposed secrets.
"""

import math
import os
import re
from collections import Counter
from typing import Optional

from . import Finding
from .rules import RULES, Rule

# Filenames to skip entirely (package managers lock files with non-.lock extensions)
_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "Gemfile.lock",
    "composer.lock", "poetry.lock", "Pipfile.lock",
}

# Directories to skip entirely
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "vendor", "bower_components", ".terraform",
}

# File extensions that are guaranteed to be binary / non-secret
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".mov", ".avi", ".mkv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".lock",    # package-lock.json, yarn.lock, Gemfile.lock
    ".min.js",  # handled separately below
    ".map",
}

# Lines that are clearly comments listing placeholder patterns
_PLACEHOLDER_RE = re.compile(
    r"(your[-_]?|<your|example|placeholder|change[-_]?me|"
    r"dummy|xxx+|000+|111+|abc+|replace[-_]?me|insert[-_]?|"
    r"here>?|todo|fixme|sample|fake|mock|n/?a)",
    re.IGNORECASE,
)

# Maximum line length to scan (skip minified / generated files)
_MAX_LINE_LEN = 2000

# Minimum entropy for generic rules (SS014, SS015)
_MIN_ENTROPY = 3.2


# ── Public API ────────────────────────────────────────────────────────────────

def scan_file(file_path: str) -> list[Finding]:
    """
    Scan a single text file and return all secret findings.

    Raises:
        FileNotFoundError: if the file does not exist.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")

    if _is_binary(file_path):
        return []

    findings: list[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, raw in enumerate(fh, start=1):
                if len(raw) > _MAX_LINE_LEN:
                    continue   # skip minified / generated lines
                for rule in RULES:
                    hit = _check_line(raw, rule)
                    if hit:
                        secret, masked_line = hit
                        findings.append(Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            name=rule.name,
                            file_path=file_path,
                            line=lineno,
                            line_content=masked_line.rstrip(),
                            secret_preview=_mask(secret),
                            detail=rule.detail,
                            fix=rule.fix,
                        ))
    except (OSError, PermissionError):
        pass

    return findings


def scan_directory(directory: str) -> list[Finding]:
    """
    Recursively scan all text files under *directory*.

    Raises:
        NotADirectoryError: if the path is not a directory.
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Diretório não encontrado: {directory}")

    findings: list[Finding] = []
    for root, dirs, files in os.walk(directory):
        # Prune directories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        for fname in files:
            if _should_skip_file(fname):
                continue
            full = os.path.join(root, fname)
            findings.extend(scan_file(full))

    return findings


# ── Internal helpers ──────────────────────────────────────────────────────────

def _check_line(line: str, rule: Rule) -> Optional[tuple[str, str]]:
    """
    Return (raw_secret, masked_line) if the rule fires on this line, else None.
    Applies false-positive filters before returning.
    """
    match = rule.pattern.search(line)
    if not match:
        return None

    secret = match.group(rule.secret_group)

    # Strip surrounding quotes
    secret = secret.strip("'\"` \t")

    if not secret or len(secret) < 6:
        return None

    # Placeholder and entropy checks are only applied to generic rules
    # (SS014, SS015). Specific-format rules (AWS, GitHub, Stripe…) are
    # precise enough that the pattern itself is the filter.
    if rule.entropy_check:
        if _is_placeholder(secret):
            return None
        if _entropy(secret) < _MIN_ENTROPY:
            return None

    masked_line = line[: match.start(rule.secret_group)] + _mask(secret) + line[match.end(rule.secret_group):]
    return secret, masked_line


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder rather than a real secret."""
    if _PLACEHOLDER_RE.search(value):
        return True
    # Reject if it contains a variable expansion or function call
    if re.search(r"[\$\(\)\{\}]", value):
        return True
    # Reject if all characters are the same (e.g. "aaaaaaa")
    unique = set(value.lower().replace("-", "").replace("_", ""))
    if len(unique) < 3:
        return True
    return False


def _entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _mask(secret: str) -> str:
    """Show only the first 4 and last 4 characters of a secret."""
    if len(secret) <= 10:
        return secret[:2] + "****"
    return secret[:4] + "..." + secret[-4:]


def _is_binary(path: str) -> bool:
    """Return True if the file appears to be binary (contains null bytes in first 8 KB)."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _should_skip_file(fname: str) -> bool:
    """Return True for filenames / extensions we never want to scan."""
    lower = fname.lower()
    if lower in _SKIP_FILENAMES:
        return True
    if lower.endswith(".min.js") or lower.endswith(".min.css"):
        return True
    _, ext = os.path.splitext(lower)
    return ext in _SKIP_EXTENSIONS

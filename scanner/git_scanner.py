"""
Scans git commit history for secrets introduced in any commit.

Only lines *added* in a diff (starting with '+') are checked, so secrets
that were always present in the codebase and never removed are detected
at the commit where they were first introduced.
"""

import re
import subprocess
from typing import Optional

from . import Finding
from .file_scanner import _check_line, _should_skip_file
from .rules import RULES

# Regex to detect the start of a new file section in a unified diff
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
# Regex to detect a hunk header line
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


# ── Public API ────────────────────────────────────────────────────────────────

def is_git_repo(path: str) -> bool:
    """Return True if *path* is inside a git repository."""
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=path,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def scan_git_history(repo_path: str, max_commits: int = 100) -> list[Finding]:
    """
    Scan the last *max_commits* commits across all branches for exposed secrets.

    Returns findings grouped by commit, file, and line number.

    Raises:
        RuntimeError: if git is not available or the path is not a git repo.
    """
    if not _git_available():
        raise RuntimeError("git não encontrado. Instale git para usar o scan de histórico.")

    if not is_git_repo(repo_path):
        raise RuntimeError(f"'{repo_path}' não é um repositório git.")

    commits = _get_commits(repo_path, max_commits)
    if not commits:
        return []

    findings: list[Finding] = []
    for sha, message in commits:
        diff = _get_commit_diff(repo_path, sha)
        if diff:
            findings.extend(_scan_diff(diff, sha, message))

    return findings


# ── Internal helpers ──────────────────────────────────────────────────────────

def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _get_commits(repo_path: str, limit: int) -> list[tuple[str, str]]:
    """Return a list of (sha, subject) for the last *limit* commits on all branches."""
    result = subprocess.run(
        ["git", "log", "--all", f"--max-count={limit}", "--format=%H\t%s"],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []

    commits = []
    for line in result.stdout.splitlines():
        if "\t" in line:
            sha, _, subject = line.partition("\t")
            commits.append((sha.strip(), subject.strip()))
    return commits


def _get_commit_diff(repo_path: str, sha: str) -> str:
    """Return the unified diff for a single commit."""
    result = subprocess.run(
        ["git", "show", sha, "--format=", "-U0"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        errors="ignore",
    )
    return result.stdout if result.returncode == 0 else ""


def _scan_diff(diff: str, sha: str, message: str) -> list[Finding]:
    """
    Parse a unified diff and scan only added lines ('+') for secrets.
    Tracks the current file and line number from diff headers.
    """
    findings: list[Finding] = []
    current_file: Optional[str] = None
    current_line = 1

    for raw in diff.splitlines():
        # New file section
        file_match = _DIFF_FILE_RE.match(raw)
        if file_match:
            current_file = file_match.group(1)
            current_line = 1
            continue

        # Hunk header — update the starting line number
        hunk_match = _HUNK_RE.match(raw)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        # Skip binary / irrelevant files
        if current_file and _should_skip_file(current_file):
            continue

        # Only check added lines
        if raw.startswith("+") and not raw.startswith("+++"):
            line_content = raw[1:]   # strip the leading '+'
            for rule in RULES:
                hit = _check_line(line_content, rule)
                if hit:
                    secret, masked = hit
                    findings.append(Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        name=rule.name,
                        file_path=current_file or "(desconhecido)",
                        line=current_line,
                        line_content=masked.rstrip(),
                        secret_preview=_preview(secret),
                        detail=rule.detail,
                        fix=rule.fix,
                        commit=sha[:12],
                        commit_message=message,
                    ))
            current_line += 1
        elif not raw.startswith("-"):
            # Context line — advance the line counter
            current_line += 1

    return findings


def _preview(secret: str) -> str:
    if len(secret) <= 10:
        return secret[:2] + "****"
    return secret[:4] + "..." + secret[-4:]

"""
Scans Git history and staged changes for secrets.

Only lines *added* by a diff are checked, so a secret is reported at the commit that introduced
it, even if it was removed later. The same secret in the same file is reported once, at the
oldest commit.
"""

from __future__ import annotations

import re
import subprocess
from typing import Optional

from . import Finding
from .file_scanner import _should_skip_file, findings_for_line
from .ignore import IgnoreMatcher

_DIFF_FILE_RE = re.compile(r"^\+\+\+ (?:b/(.+)|/dev/null)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_GIT = ["git", "-c", "core.quotepath=off"]


def _git(repo_path: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*_GIT, *args], cwd=repo_path, capture_output=True, text=True, errors="ignore"
    )


def git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def is_git_repo(path: str) -> bool:
    try:
        return _git(path, "rev-parse", "--is-inside-work-tree").returncode == 0
    except (FileNotFoundError, NotADirectoryError):
        return False


def _require_repo(repo_path: str) -> None:
    if not git_available():
        raise RuntimeError("git not found. Install git to scan history or staged changes.")
    if not is_git_repo(repo_path):
        raise RuntimeError(f"'{repo_path}' is not a git repository.")


def scan_git_history(
    repo_path: str, max_commits: int = 100, ignore: Optional[IgnoreMatcher] = None
) -> list[Finding]:
    """Scan the last *max_commits* commits of every branch (0 = no limit)."""
    _require_repo(repo_path)
    args = ["log", "--all", "--format=%H%x09%s"]
    if max_commits > 0:
        args.insert(2, f"--max-count={max_commits}")
    res = _git(repo_path, *args)
    if res.returncode != 0:
        raise RuntimeError(f"git log failed: {res.stderr.strip()}")

    commits = []
    for line in res.stdout.splitlines():
        sha, _, subject = line.partition("\t")
        if sha:
            commits.append((sha.strip(), subject.strip()))

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for sha, subject in reversed(commits):            # oldest first: keep the introducing commit
        diff = _git(repo_path, "show", sha, "--format=", "-U0", "--no-color")
        if diff.returncode != 0:
            continue
        for f in _scan_diff(diff.stdout, sha[:12], subject, ignore):
            key = (f.fingerprint, f.file_path)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    return findings


def scan_staged(repo_path: str = ".", ignore: Optional[IgnoreMatcher] = None) -> list[Finding]:
    """Scan only what is staged for the next commit (use as a pre-commit hook)."""
    _require_repo(repo_path)
    res = _git(repo_path, "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR")
    if res.returncode != 0:
        raise RuntimeError(f"git diff failed: {res.stderr.strip()}")
    return _scan_diff(res.stdout, "staged", "staged changes", ignore)


def _scan_diff(
    diff: str, commit: str, message: str, ignore: Optional[IgnoreMatcher] = None
) -> list[Finding]:
    findings: list[Finding] = []
    current_file: Optional[str] = None
    line_no = 1

    for raw in diff.splitlines():
        file_match = _DIFF_FILE_RE.match(raw)
        if file_match:
            current_file = file_match.group(1)          # None for /dev/null (deleted file)
            continue
        hunk = _HUNK_RE.match(raw)
        if hunk:
            line_no = int(hunk.group(1))
            continue
        if not current_file or not raw.startswith("+") or raw.startswith("+++"):
            continue
        if _should_skip_file(current_file) or (ignore and ignore.matches(current_file)):
            continue
        findings.extend(
            findings_for_line(raw[1:], current_file, line_no, commit=commit, commit_message=message)
        )
        line_no += 1
    return findings

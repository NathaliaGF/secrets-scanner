"""
Baseline: accept the findings that exist today and fail only on new ones.

The baseline stores fingerprints (truncated SHA-256 of rule id + secret), never the secrets.
"""

from __future__ import annotations

import json
from typing import Iterable

from . import Finding


def _key(f: Finding) -> tuple[str, str]:
    return f.fingerprint, f.file_path


def write_baseline(path: str, findings: Iterable[Finding]) -> int:
    items = sorted(
        {_key(f): {"fingerprint": f.fingerprint, "rule": f.rule_id, "file": f.file_path} for f in findings}.values(),
        key=lambda i: (i["file"], i["rule"], i["fingerprint"]),
    )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "findings": items}, fh, indent=2)
        fh.write("\n")
    return len(items)


def load_baseline(path: str) -> set[tuple[str, str]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"{path}: not a secrets-scanner baseline (version 1)")
    return {(i["fingerprint"], i["file"]) for i in data.get("findings", [])}


def apply_baseline(findings: list[Finding], accepted: set[tuple[str, str]]) -> list[Finding]:
    return [f for f in findings if _key(f) not in accepted]

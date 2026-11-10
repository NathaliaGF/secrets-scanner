import re
from pathlib import Path

from secrets_scanner.file_scanner import scan_directory, scan_file
from secrets_scanner.rules import RULES

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"


def test_clean_samples_have_no_findings():
    for name in ("clean.py", "clean.env", "clean.yml"):
        assert scan_file(str(SAMPLES / name)) == [], name


def test_dirty_samples_are_detected():
    py = {f.rule_id for f in scan_file(str(SAMPLES / "dirty.py"))}
    assert {"SS001", "SS002", "SS003", "SS006", "SS010", "SS011", "SS012", "SS014", "SS015"} <= py
    env = {f.rule_id for f in scan_file(str(SAMPLES / "dirty.env"))}
    assert {"SS001", "SS006", "SS009", "SS011", "SS014", "SS015"} <= env
    yml = {f.rule_id for f in scan_file(str(SAMPLES / "dirty.yml"))}
    assert {"SS014", "SS015"} <= yml


def test_project_source_scans_clean():
    """The scanner must not flag its own source (tests and samples excluded)."""
    found = scan_directory(str(ROOT / "secrets_scanner"))
    assert found == [], found


def test_rule_ids_are_unique_and_documented():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing = [i for i in ids if not re.search(rf"\b{i}\b", readme)]
    assert not missing, f"rules missing from README: {missing}"

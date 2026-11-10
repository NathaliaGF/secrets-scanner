import json

import pytest

from secrets_scanner.baseline import apply_baseline, load_baseline, write_baseline
from secrets_scanner.file_scanner import ScanStats, scan_directory
from secrets_scanner.ignore import IgnoreMatcher

SECRET_LINE = 'password = "Xk9#mQ2vLp7zRt"\n'


@pytest.mark.parametrize("pattern,path,is_dir,expected", [
    ("*.md", "README.md", False, True),
    ("*.md", "docs/guide.md", False, True),
    ("tests/", "tests/a.py", False, True),
    ("tests/", "src/tests/a.py", False, True),
    ("tests/", "tests", True, True),
    ("tests/", "tests", False, False),          # a *file* called tests is not a directory
    ("/docs/build", "docs/build/x.py", False, True),
    ("/docs/build", "src/docs/build/x.py", False, False),
    ("docs/**/*.txt", "docs/a/b/c.txt", False, True),
    (".env", ".env", False, True),
    ("# comment", "comment", False, False),
    ("src", "src/a.py", False, True),
    ("src", "other/a.py", False, False),
])
def test_ignore_matcher(pattern, path, is_dir, expected):
    assert IgnoreMatcher([pattern]).matches(path, is_dir=is_dir) is expected


def test_from_file_missing_returns_empty(tmp_path):
    assert IgnoreMatcher.from_file(str(tmp_path / "nope")).patterns == []


def test_scan_directory_honours_ignore_and_reports_relative_paths(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "samples").mkdir()
    (tmp_path / "app" / "a.py").write_text(SECRET_LINE)
    (tmp_path / "samples" / "b.py").write_text(SECRET_LINE)
    found = scan_directory(str(tmp_path), ignore=IgnoreMatcher(["samples/"]))
    assert [f.file_path for f in found] == ["app/a.py"]


def test_skipped_files_are_reported(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 5000)
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01\x02")
    stats = ScanStats()
    scan_directory(str(tmp_path), max_file_size=1000, stats=stats)
    reasons = dict(stats.skipped)
    assert "larger" in reasons["big.txt"]
    assert reasons["bin.dat"] == "binary"
    assert stats.files_scanned == 0


def test_baseline_roundtrip_hides_known_and_keeps_new(tmp_path):
    (tmp_path / "a.py").write_text(SECRET_LINE)
    known = scan_directory(str(tmp_path))
    base = tmp_path / "base.json"
    assert write_baseline(str(base), known) == 1

    (tmp_path / "b.py").write_text('api_key = "9fA3kLm2Qx7ZpR4tVb8NzzQ"\n')
    now = scan_directory(str(tmp_path))
    assert len(now) == 2
    left = apply_baseline(now, load_baseline(str(base)))
    assert [f.file_path for f in left] == ["b.py"]


def test_baseline_never_stores_the_secret(tmp_path):
    (tmp_path / "a.py").write_text(SECRET_LINE)
    base = tmp_path / "base.json"
    write_baseline(str(base), scan_directory(str(tmp_path)))
    assert "Xk9#mQ2vLp7zRt" not in base.read_text()


def test_load_baseline_rejects_other_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"hello": 1}))
    with pytest.raises(ValueError):
        load_baseline(str(p))

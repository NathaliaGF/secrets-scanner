import json
import os
import subprocess

import pytest

from secrets_scanner.cli import main

SECRET = 'password = "Xk9#mQ2vLp7zRt"\n'
MEDIUM_ONLY = SECRET                                  # SS014 is MEDIUM
HIGH_ONE = 'key = "AIza' + "SyD-9tSrke72Dfw4eqq3HN5YAsDFGHA1234" + '"\n'   # SS006 is HIGH


def run(capsys, *argv):
    with pytest.raises(SystemExit) as exc:
        main(list(argv))
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


def test_clean_directory_exits_0(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("import os\nX = os.environ.get('X')\n")
    code, out, _ = run(capsys, "--dir", str(tmp_path))
    assert code == 0 and "No secrets found" in out


def test_findings_exit_1(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    code, out, _ = run(capsys, "--dir", str(tmp_path))
    assert code == 1 and "SS014" in out


def test_severity_is_a_minimum_and_controls_exit_code(tmp_path, capsys):
    """Regression: --severity HIGH with only MEDIUM findings used to exit 1."""
    (tmp_path / "a.py").write_text(MEDIUM_ONLY)
    assert run(capsys, "--dir", str(tmp_path), "--severity", "HIGH")[0] == 0
    (tmp_path / "b.py").write_text(HIGH_ONE)
    code, out, _ = run(capsys, "--dir", str(tmp_path), "--severity", "HIGH")
    assert code == 1 and "SS006" in out and "SS014" not in out


def test_exit_zero(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    assert run(capsys, "--dir", str(tmp_path), "--exit-zero")[0] == 0


def test_missing_path_exits_2(tmp_path, capsys):
    code, _, err = run(capsys, "--dir", str(tmp_path / "nope"))
    assert code == 2 and "[ERROR]" in err
    assert run(capsys, "--file", str(tmp_path / "nope.py"))[0] == 2


def test_json_output_is_parseable(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    code, out, _ = run(capsys, "--dir", str(tmp_path), "--output", "json")
    data = json.loads(out)
    assert code == 1 and data["summary"]["total_findings"] == 1
    assert data["findings"][0]["file"] == "a.py"
    assert "Xk9#mQ2vLp7zRt" not in out


def test_sarif_to_file(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    target = tmp_path / "out.sarif"
    code, out, _ = run(capsys, "--dir", str(tmp_path), "--output", "sarif", "--output-file", str(target))
    assert code == 1 and out == ""
    assert json.loads(target.read_text())["version"] == "2.1.0"


def test_secretsignore_in_scanned_dir_is_used(tmp_path, capsys):
    (tmp_path / "keep").mkdir()
    (tmp_path / "skip").mkdir()
    (tmp_path / "keep" / "a.py").write_text(SECRET)
    (tmp_path / "skip" / "b.py").write_text(SECRET)
    (tmp_path / ".secretsignore").write_text("# fixtures\nskip/\n")
    _, out, _ = run(capsys, "--dir", str(tmp_path), "--output", "json")
    assert [f["file"] for f in json.loads(out)["findings"]] == ["keep/a.py"]


def test_exclude_flag(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    assert run(capsys, "--dir", str(tmp_path), "--exclude", "a.py")[0] == 0


def test_baseline_flow(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    base = tmp_path / "base.json"
    assert run(capsys, "--dir", str(tmp_path), "--update-baseline", str(base))[0] == 0
    assert run(capsys, "--dir", str(tmp_path), "--baseline", str(base))[0] == 0
    (tmp_path / "new.py").write_text(HIGH_ONE)
    assert run(capsys, "--dir", str(tmp_path), "--baseline", str(base))[0] == 1


def test_bad_baseline_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    (tmp_path / "a.py").write_text(SECRET)
    assert run(capsys, "--dir", str(tmp_path), "--baseline", str(bad))[0] == 2


def test_list_rules(capsys):
    code, out, _ = run(capsys, "--list-rules")
    assert code == 0 and "SS001" in out and "SS030" in out


def test_requires_a_source(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_no_ansi_when_piped(tmp_path, capsys):
    (tmp_path / "a.py").write_text(SECRET)
    assert "\033[" not in run(capsys, "--dir", str(tmp_path))[1]


# ── git ───────────────────────────────────────────────────────────────────────

def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    return tmp_path


def test_history_finds_removed_secret_and_reports_it_once(repo, capsys):
    (repo / "cfg.py").write_text(SECRET)
    git(repo, "add", "."); git(repo, "commit", "-qm", "add config")
    (repo / "cfg.py").write_text(SECRET + "# touched\n")        # same secret stays in a later diff context
    git(repo, "commit", "-qam", "touch")
    (repo / "cfg.py").write_text("import os\n")
    git(repo, "commit", "-qam", "remove secret")

    code, out, _ = run(capsys, "--dir", str(repo), "--git", "--output", "json")
    data = json.loads(out)
    assert code == 1
    assert data["summary"]["total_findings"] == 1                # removed from tree, still in history
    assert data["findings"][0]["commit_message"] == "add config"


def test_tree_finding_is_not_duplicated_by_history(repo, capsys):
    (repo / "cfg.py").write_text(SECRET)
    git(repo, "add", "."); git(repo, "commit", "-qm", "add")
    _, out, _ = run(capsys, "--dir", str(repo), "--git", "--output", "json")
    assert json.loads(out)["summary"]["total_findings"] == 1


def test_git_flag_on_non_repo_exits_2(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert run(capsys, "--dir", str(tmp_path), "--git")[0] == 2


def test_staged_scan(repo, capsys, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "clean.py").write_text("x = 1\n")
    git(repo, "add", "."); git(repo, "commit", "-qm", "init")
    (repo / "new.py").write_text(SECRET)
    assert run(capsys, "--staged")[0] == 0                       # not staged yet
    git(repo, "add", "new.py")
    code, out, _ = run(capsys, "--staged", "--output", "json")
    data = json.loads(out)
    assert code == 1 and data["findings"][0]["file"] == "new.py" and data["findings"][0]["commit"] == "staged"


def test_staged_ignores_deleted_files(repo, capsys, monkeypatch):
    monkeypatch.chdir(repo)
    (repo / "old.py").write_text(SECRET)
    git(repo, "add", "."); git(repo, "commit", "-qm", "init")
    git(repo, "rm", "-q", "old.py")
    assert run(capsys, "--staged")[0] == 0

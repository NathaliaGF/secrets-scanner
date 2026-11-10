import json

from secrets_scanner import Finding
from secrets_scanner.report import (filter_by_severity, render_json, render_sarif,
                                    render_terminal, risk_level)
from secrets_scanner.rules import RULES


def finding(sev="CRITICAL", rule="SS001", path="a.py", line=3, commit=None):
    return Finding(rule, sev, "AWS Access Key ID", path, line, 'k = "AKIA...MPLE"', "AKIA...MPLE",
                   "detail", "fix", fingerprint="abc123", commit=commit)


def test_filter_by_severity_is_a_minimum():
    fs = [finding("CRITICAL"), finding("HIGH"), finding("MEDIUM"), finding("LOW")]
    assert [f.severity for f in filter_by_severity(fs, "HIGH")] == ["CRITICAL", "HIGH"]
    assert len(filter_by_severity(fs, None)) == 4
    assert len(filter_by_severity(fs, "low")) == 4


def test_risk_level():
    assert risk_level([]) is None
    assert risk_level([finding("MEDIUM"), finding("HIGH")]) == "HIGH"


def test_terminal_without_color_has_no_escape_codes():
    out = render_terminal([finding()], "proj", 4, color=False)
    assert "\033[" not in out and "AKIA...MPLE" in out and "Files scanned: 4" in out


def test_terminal_reports_skipped_files():
    out = render_terminal([], "proj", 1, [("big.txt", "larger than 10 bytes")])
    assert "No secrets found" in out and "big.txt" in out


def test_json_shape():
    data = json.loads(render_json([finding(), finding("MEDIUM", "SS014")], "proj", 2))
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["by_severity"]["CRITICAL"] == 1
    assert data["findings"][0]["fingerprint"] == "abc123"
    assert data["tool"]["name"] == "secrets-scanner"


def test_sarif_is_valid_shape_and_has_every_rule():
    sarif = json.loads(render_sarif([finding(commit="abc123456789")]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(RULES)
    (res,) = run["results"]
    assert res["ruleId"] == "SS001" and res["level"] == "error"
    assert res["ruleIndex"] == [r.id for r in RULES].index("SS001")
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "a.py" and loc["region"]["startLine"] == 3
    assert res["partialFingerprints"]["secretFingerprint/v1"] == "abc123"
    assert res["properties"]["commit"] == "abc123456789"


def test_sarif_levels_and_security_severity():
    rules = {r["id"]: r for r in json.loads(render_sarif([]))["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["SS001"]["defaultConfiguration"]["level"] == "error"
    assert rules["SS014"]["defaultConfiguration"]["level"] == "warning"
    assert float(rules["SS001"]["properties"]["security-severity"]) > float(
        rules["SS014"]["properties"]["security-severity"])


def test_sarif_never_contains_the_full_secret():
    assert "AKIAIOSFODNN7EXAMPLE" not in render_sarif([finding()])

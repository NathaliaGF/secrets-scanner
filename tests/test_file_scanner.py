"""
Tests for file_scanner helpers: masking, entropy, placeholder detection,
binary detection, and directory scan.
"""

import os
import pytest

from scanner.file_scanner import (
    _entropy,
    _is_placeholder,
    _is_binary,
    _mask,
    _should_skip_file,
    scan_file,
    scan_directory,
)


# ── Entropy ───────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_random_string_has_high_entropy(self):
        assert _entropy("xK9mN2pL8qR5vT7w") > 3.0

    def test_repeated_chars_has_low_entropy(self):
        assert _entropy("aaaaaaaaaaaaa") < 1.0

    def test_empty_string_returns_zero(self):
        assert _entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert _entropy("a") == 0.0


# ── Placeholder detection ─────────────────────────────────────────────────────

class TestIsPlaceholder:
    def test_changeme_is_placeholder(self):
        assert _is_placeholder("changeme")

    def test_your_api_key_is_placeholder(self):
        assert _is_placeholder("your-api-key-here")

    def test_example_is_placeholder(self):
        assert _is_placeholder("example-secret")

    def test_xxx_is_placeholder(self):
        assert _is_placeholder("xxxxxxxxxxxxxxxx")

    def test_real_looking_secret_is_not_placeholder(self):
        assert not _is_placeholder("sk-prod-xK9mN2pL8qR5vT")

    def test_function_call_is_placeholder(self):
        assert _is_placeholder("os.environ.get('KEY')")

    def test_all_same_chars_is_placeholder(self):
        assert _is_placeholder("aaaaaaaaaaaaaaaa")


# ── Mask ──────────────────────────────────────────────────────────────────────

class TestMask:
    def test_long_secret_is_masked(self):
        result = _mask("abcdEFGH12345678ijklMNOP")
        assert "..." in result
        assert result.startswith("abcd")
        assert result.endswith("MNOP")

    def test_short_secret_is_partially_masked(self):
        result = _mask("abc123")
        assert "****" in result

    def test_full_secret_not_exposed(self):
        secret = "abcdEFGH12345678ijklMNOP12345678"
        result = _mask(secret)
        assert secret not in result


# ── Binary detection ──────────────────────────────────────────────────────────

class TestIsBinary:
    def test_text_file_is_not_binary(self, tmp_path):
        f = tmp_path / "hello.py"
        f.write_text("print('hello')\n", encoding="utf-8")
        assert not _is_binary(str(f))

    def test_binary_file_is_detected(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02\x03binary content")
        assert _is_binary(str(f))


# ── File extension filter ─────────────────────────────────────────────────────

class TestShouldSkipFile:
    def test_png_is_skipped(self):
        assert _should_skip_file("image.png")

    def test_lock_is_skipped(self):
        assert _should_skip_file("package-lock.json")

    def test_min_js_is_skipped(self):
        assert _should_skip_file("bundle.min.js")

    def test_py_is_not_skipped(self):
        assert not _should_skip_file("app.py")

    def test_env_is_not_skipped(self):
        assert not _should_skip_file(".env")

    def test_yml_is_not_skipped(self):
        assert not _should_skip_file("config.yml")


# ── scan_file ─────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_file("/tmp/this_does_not_exist_secrets_scanner.py")

    def test_aws_key_detected(self, tmp_path):
        f = tmp_path / "creds.py"
        f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        findings = scan_file(str(f))
        assert any(x.rule_id == "SS001" for x in findings)

    def test_github_token_detected(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n', encoding="utf-8")
        findings = scan_file(str(f))
        assert any(x.rule_id == "SS003" for x in findings)

    def test_clean_file_has_no_findings(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text("import os\nTOKEN = os.environ.get('TOKEN')\n", encoding="utf-8")
        findings = scan_file(str(f))
        assert findings == []

    def test_line_number_is_correct(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            "line1 = 'safe'\n"
            "line2 = 'safe'\n"
            'line3 = "AKIAIOSFODNN7EXAMPLE"\n',
            encoding="utf-8",
        )
        findings = scan_file(str(f))
        aws = next((x for x in findings if x.rule_id == "SS001"), None)
        assert aws is not None
        assert aws.line == 3

    def test_secret_is_masked_in_line_content(self, tmp_path):
        f = tmp_path / "app.py"
        secret = "AKIAIOSFODNN7EXAMPLE"
        f.write_text(f'KEY = "{secret}"\n', encoding="utf-8")
        findings = scan_file(str(f))
        assert findings
        # The raw secret should NOT appear verbatim in line_content
        assert secret not in findings[0].line_content


# ── scan_directory ────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_not_a_directory_raises(self):
        with pytest.raises(NotADirectoryError):
            scan_directory("/tmp/this_is_not_a_real_directory_abc123")

    def test_finds_secrets_in_nested_files(self, tmp_path):
        subdir = tmp_path / "config"
        subdir.mkdir()
        (subdir / "secrets.py").write_text(
            'TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n',
            encoding="utf-8",
        )
        findings = scan_directory(str(tmp_path))
        assert any(x.rule_id == "SS003" for x in findings)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(
            'const key = "AKIAIOSFODNN7EXAMPLE";\n',
            encoding="utf-8",
        )
        findings = scan_directory(str(tmp_path))
        assert findings == []

    def test_skips_git_directory(self, tmp_path):
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config").write_text(
            'token = "ghp_1234567890abcdef1234567890abcdef1234"\n',
            encoding="utf-8",
        )
        findings = scan_directory(str(tmp_path))
        assert findings == []

    def test_clean_directory_has_no_findings(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import os\nKEY = os.environ.get('KEY')\n",
            encoding="utf-8",
        )
        findings = scan_directory(str(tmp_path))
        assert findings == []

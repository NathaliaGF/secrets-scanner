"""Regression tests for the detection gaps found in the first audit of the project."""

import pytest

from secrets_scanner.file_scanner import find_secrets, mask_line


def ids(line: str) -> list[str]:
    return [h.rule.id for h in find_secrets(line)]


@pytest.mark.parametrize("line,expected", [
    # unquoted assignments: .env, YAML, ini
    ("DB_PASSWORD=Xk9#mQ2vLp7zRt", "SS014"),
    ("password: Xk9#mQ2vLp7zRt", "SS014"),
    ("password = Xk9#mQ2vLp7zRt", "SS014"),
    ("API_KEY=9fA3kLm2Qx7ZpR4tVb8N", "SS015"),
    ("client_secret: 9fA3kLm2Qx7ZpR4tVb8Nq", "SS015"),
    ("SECRET_TOKEN=9fA3kLm2Qx7ZpR4tVb8NqLw5", "SS030"),
    # JSON
    ('{"password": "Xk9#mQ2vLp7zRt"}', "SS014"),
    # passphrase with spaces in quotes
    ('password = "correct horse battery"', "SS014"),
    # words that the old placeholder filter wrongly dropped ("na", "abc", "mock" inside a word)
    ('password = "Banana#Secure99"', "SS014"),
    ('password = "Hannah!Montana42"', "SS014"),
    # key formats
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "SS010"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "SS010"),
    ("-----BEGIN PRIVATE KEY-----", "SS010"),
    ("key = ASIAIOSFODNN7EXAMPLE", "SS001"),
])
def test_detects(line, expected):
    assert expected in ids(line)


@pytest.mark.parametrize("line", [
    "password = os.environ.get('DB_PASS')",
    "password = get_password()",
    "password = request.form['password']",
    "password = config.db.password",
    "password: ${DB_PASSWORD}",
    "password: {{ vault_db_password }}",
    "password: <your-password>",
    "def login(user, password: str):",
    "password: required",
    'api_key = "your-api-key-here-please"',
    'password = "changeme"',
    "PWD=/home/user/projects/app",
    "key = 'akiaabcdefghijklmnop'",          # AWS ids are upper case
    'if password == "abc":',
    "token = request.headers.get('Authorization')",
])
def test_does_not_flag(line):
    assert ids(line) == []


def test_every_secret_on_a_line_is_masked():
    line = 'x="AKIAIOSFODNN7EXAMPLE"; password="Xk9#mQ2vLp7zRt"'
    masked = mask_line(line, find_secrets(line))
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "Xk9#mQ2vLp7zRt" not in masked


def test_specific_rule_wins_over_generic_on_same_value():
    from tests.fakes import github_pat
    assert ids(f'api_key = "{github_pat()}"') == ["SS003"]


def test_db_url_masks_only_the_password():
    line = "DATABASE_URL=postgresql://admin:SuperSenhaSecreta123@db:5432/app"
    (hit,) = find_secrets(line)
    assert hit.rule.id == "SS011"
    assert mask_line(line, [hit]).startswith("DATABASE_URL=postgresql://admin:")
    assert "SuperSenhaSecreta123" not in mask_line(line, [hit])


def test_db_url_with_variable_is_not_a_secret():
    assert ids("DATABASE_URL=postgresql://user:${DB_PASS}@host/db") == []


@pytest.mark.parametrize("line,expect_hit", [
    ('password = "Xk9#mQ2vLp7zRt"  # secrets-scanner:ignore', False),
    ('password = "Xk9#mQ2vLp7zRt"  # secrets-scanner:ignore SS014', False),
    ('password = "Xk9#mQ2vLp7zRt"  # secrets-scanner:ignore SS001', True),
])
def test_inline_ignore(line, expect_hit):
    assert bool(ids(line)) is expect_hit


def test_private_key_header_is_shown_not_masked():
    (hit,) = find_secrets("# -----BEGIN OPENSSH PRIVATE KEY-----")
    assert hit.preview == "-----BEGIN OPENSSH PRIVATE KEY-----"


def test_already_masked_values_do_not_alert_again():
    """A report pasted into docs, issues or logs must not trigger a new finding."""
    for line in ('DATABASE_URL = "postgresql://admin:Supe...a123@db.example.com:5432/producao"',
                 'db_password = "Tr0u...eKey"',
                 'password = "ab****"'):
        assert ids(line) == [], line

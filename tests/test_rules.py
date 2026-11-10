"""
Unit tests — one test class per rule (SS001-SS015).
Each test verifies that the rule fires on a real-looking fake secret
and does NOT fire on safe alternatives.
"""

import pytest
from secrets_scanner.rules import RULES_BY_ID
from secrets_scanner.file_scanner import _check_line


def fires(rule_id: str, line: str) -> bool:
    rule = RULES_BY_ID[rule_id]
    return _check_line(line, rule) is not None


def no_fire(rule_id: str, line: str) -> bool:
    return not fires(rule_id, line)


# ── SS001 — AWS Access Key ID ─────────────────────────────────────────────────

class TestSS001:
    def test_aws_key_triggers(self):
        assert fires("SS001", 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')

    def test_aws_key_in_env_triggers(self):
        assert fires("SS001", "AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE")

    def test_non_aws_pattern_passes(self):
        assert no_fire("SS001", 'key = "BKIAIOSFODNN7EXAMPLE"')

    def test_short_akia_passes(self):
        assert no_fire("SS001", 'prefix = "AKIA123"')


# ── SS002 — AWS Secret Access Key ─────────────────────────────────────────────

class TestSS002:
    def test_secret_key_assignment_triggers(self):
        # AWS example secret key is exactly 40 characters
        assert fires("SS002", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')

    def test_env_format_triggers(self):
        assert fires("SS002", "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_env_var_reference_passes(self):
        assert no_fire("SS002", 'aws_secret_access_key = os.environ.get("AWS_SECRET")')


# ── SS003 — GitHub PAT ────────────────────────────────────────────────────────

class TestSS003:
    def test_ghp_token_triggers(self):
        assert fires("SS003", 'GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"')

    def test_token_in_url_triggers(self):
        # Token must be exactly 36 chars after ghp_
        assert fires("SS003", "git clone https://ghp_abcdefghij1234567890abcdefghij123456@github.com/repo")

    def test_non_ghp_passes(self):
        assert no_fire("SS003", 'token = "gha_1234567890abcdef1234567890abcdef1234"')

    def test_short_ghp_passes(self):
        assert no_fire("SS003", 'x = "ghp_short"')


# ── SS004 — GitHub Fine-grained Token ────────────────────────────────────────

class TestSS004:
    def test_github_pat_triggers(self):
        long_token = "A" * 82
        assert fires("SS004", f'TOKEN = "github_pat_{long_token}"')

    def test_no_match_without_prefix_passes(self):
        assert no_fire("SS004", 'TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"')


# ── SS005 — GitHub OAuth / App Token ─────────────────────────────────────────

class TestSS005:
    def test_gho_token_triggers(self):
        assert fires("SS005", 'token = "gho_1234567890abcdef1234567890abcdef1234"')

    def test_ghs_token_triggers(self):
        assert fires("SS005", 'token = "ghs_1234567890abcdef1234567890abcdef1234"')

    def test_other_prefix_passes(self):
        assert no_fire("SS005", 'token = "ghx_1234567890abcdef1234567890abcdef1234"')


# ── SS006 — Google API Key ────────────────────────────────────────────────────

class TestSS006:
    def test_google_key_triggers(self):
        assert fires("SS006", 'GOOGLE_API_KEY = "AIzaSyD-9tSrke72Dfw4eqq3HN5YAsDFGHA1234"')

    def test_short_aiza_passes(self):
        assert no_fire("SS006", 'key = "AIza123"')

    def test_wrong_prefix_passes(self):
        assert no_fire("SS006", 'key = "BIzaSyD-9tSrke72Dfw4eqq3HN5YAsDFGHA1234"')


# ── SS007 — Stripe Secret Key ─────────────────────────────────────────────────

class TestSS007:
    def test_stripe_live_secret_triggers(self):
        key = "sk_" + "live_" + "FAKEKEY0FAKEKEY0FAKEKEY0FAKE"
        assert fires("SS007", f'STRIPE_KEY = "{key}"')

    def test_stripe_test_passes(self):
        key = "sk_" + "test_" + "FAKEKEY0FAKEKEY0FAKEKEY0FAKE"
        assert no_fire("SS007", f'STRIPE_KEY = "{key}"')


# ── SS008 — Stripe Publishable Key ───────────────────────────────────────────

class TestSS008:
    def test_stripe_live_pub_triggers(self):
        key = "pk_" + "live_" + "FAKEKEY0FAKEKEY0FAKEKEY0FAKE"
        assert fires("SS008", f'STRIPE_PK = "{key}"')

    def test_stripe_test_pub_passes(self):
        key = "pk_" + "test_" + "FAKEKEY0FAKEKEY0FAKEKEY0FAKE"
        assert no_fire("SS008", f'STRIPE_PK = "{key}"')


# ── SS009 — Slack Token ───────────────────────────────────────────────────────

class TestSS009:
    def test_slack_bot_token_triggers(self):
        assert fires("SS009", 'SLACK_TOKEN = "xoxb-FAKE000000000-FAKE000000000-FAKEfakeFAKEfakeFAKEfake"')

    def test_slack_app_token_triggers(self):
        assert fires("SS009", 'token = "xoxa-2-FAKE000000000-FAKEfakeFAKEfakeFAKEfake"')

    def test_non_slack_passes(self):
        assert no_fire("SS009", 'token = "xozb-123456789012"')


# ── SS010 — Private Key ───────────────────────────────────────────────────────

class TestSS010:
    def test_rsa_key_triggers(self):
        assert fires("SS010", "-----BEGIN RSA PRIVATE KEY-----")

    def test_openssh_key_triggers(self):
        assert fires("SS010", "-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_ec_key_triggers(self):
        assert fires("SS010", "-----BEGIN EC PRIVATE KEY-----")

    def test_public_key_passes(self):
        assert no_fire("SS010", "-----BEGIN PUBLIC KEY-----")


# ── SS011 — Database URL ──────────────────────────────────────────────────────

class TestSS011:
    def test_postgres_url_triggers(self):
        assert fires("SS011", 'DB = "postgresql://admin:SenhaSecreta99@localhost:5432/db"')

    def test_mysql_url_triggers(self):
        assert fires("SS011", 'DB = "mysql://root:SenhaForte2024@db.host:3306/mydb"')

    def test_mongodb_url_triggers(self):
        assert fires("SS011", 'DB = "mongodb://user:SenhaForte@cluster.mongodb.net/db"')

    def test_url_without_password_passes(self):
        assert no_fire("SS011", 'DB = "postgresql://localhost:5432/myapp"')


# ── SS012 — JWT Token ─────────────────────────────────────────────────────────

class TestSS012:
    def test_jwt_triggers(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert fires("SS012", f'token = "{jwt}"')

    def test_short_eyj_passes(self):
        assert no_fire("SS012", 'x = "eyJhbGc.eyJzdW.short"')


# ── SS013 — SendGrid Key ──────────────────────────────────────────────────────

class TestSS013:
    def test_sendgrid_key_triggers(self):
        key = "SG." + "A" * 22 + "." + "B" * 43
        assert fires("SS013", f'SG_KEY = "{key}"')

    def test_short_sg_passes(self):
        assert no_fire("SS013", 'key = "SG.short"')


# ── SS014 — Generic Password ──────────────────────────────────────────────────

class TestSS014:
    def test_password_assignment_triggers(self):
        assert fires("SS014", 'password = "Tr0ub4dor&3xampleKey"')

    def test_passwd_triggers(self):
        assert fires("SS014", 'passwd = "SuperSenha#2024Forte"')

    def test_placeholder_passes(self):
        assert no_fire("SS014", 'password = "changeme"')

    def test_example_passes(self):
        assert no_fire("SS014", 'password = "example-password"')

    def test_env_var_reference_passes(self):
        assert no_fire("SS014", "password = os.environ.get('DB_PASS')")


# ── SS015 — Generic API Key / Token ──────────────────────────────────────────

class TestSS015:
    def test_api_key_triggers(self):
        assert fires("SS015", 'api_key = "sk-prod-xK9mN2pL8qR5vT7wY3zA6bC1dE"')

    def test_secret_key_triggers(self):
        assert fires("SS015", 'secret_key = "xK9mN2pL8qR5vT7wY3zA6bC1dE4fG5h"')

    def test_placeholder_passes(self):
        assert no_fire("SS015", 'api_key = "your-api-key-here"')

    def test_short_value_passes(self):
        assert no_fire("SS015", 'api_key = "shortkey"')


# ── Integration — sample files ────────────────────────────────────────────────

class TestSampleFiles:
    def test_dirty_py_has_findings(self):
        import os
        from secrets_scanner.file_scanner import scan_file
        sample = os.path.join(os.path.dirname(__file__), "samples", "dirty.py")
        findings = scan_file(sample)
        assert len(findings) >= 5, f"Expected ≥5 findings, got {len(findings)}"

    def test_clean_py_has_no_findings(self):
        import os
        from secrets_scanner.file_scanner import scan_file
        sample = os.path.join(os.path.dirname(__file__), "samples", "clean.py")
        findings = scan_file(sample)
        assert findings == [], f"Unexpected findings in clean.py: {[f.rule_id for f in findings]}"

    def test_dirty_env_has_findings(self):
        import os
        from secrets_scanner.file_scanner import scan_file
        sample = os.path.join(os.path.dirname(__file__), "samples", "dirty.env")
        findings = scan_file(sample)
        assert len(findings) >= 3, f"Expected ≥3 findings, got {len(findings)}"

    def test_clean_env_has_no_findings(self):
        import os
        from secrets_scanner.file_scanner import scan_file
        sample = os.path.join(os.path.dirname(__file__), "samples", "clean.env")
        findings = scan_file(sample)
        assert findings == [], f"Unexpected findings in clean.env: {[f.rule_id for f in findings]}"

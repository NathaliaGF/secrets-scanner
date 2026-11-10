"""One positive and one negative case for each rule added after SS015."""

import pytest

from secrets_scanner.file_scanner import find_secrets
from tests import fakes


def ids(line: str) -> list[str]:
    return [h.rule.id for h in find_secrets(line)]


POSITIVE = [
    ("SS016", fakes.anthropic), ("SS017", fakes.openai), ("SS018", fakes.slack_webhook),
    ("SS019", fakes.discord_webhook), ("SS020", fakes.npm), ("SS021", fakes.gitlab),
    ("SS022", fakes.pypi), ("SS023", fakes.docker_pat), ("SS024", fakes.huggingface),
    ("SS025", fakes.twilio), ("SS026", fakes.telegram), ("SS027", fakes.azure_key),
    ("SS028", fakes.shopify),
]


@pytest.mark.parametrize("rule_id,factory", POSITIVE)
def test_rule_fires(rule_id, factory):
    assert ids(f'secret_value = "{factory()}"') == [rule_id] or rule_id in ids(f'x = "{factory()}"')


@pytest.mark.parametrize("rule_id,factory", POSITIVE)
def test_rule_fires_exactly_once_on_the_token(rule_id, factory):
    assert ids(f"export X={factory()}").count(rule_id) == 1


@pytest.mark.parametrize("line", [
    'x = "sk-ant-short"',
    'x = "npm_tooshort"',
    'x = "glpat-short"',
    'x = "hf_short"',
    'x = "SKtoo-short"',
    'x = "shpat_nothex"',
    'x = "https://hooks.example.com/services/ABC"',
])
def test_short_or_malformed_values_do_not_fire(line):
    assert ids(line) == []


def test_anthropic_key_is_not_reported_as_openai():
    assert ids(f"k={fakes.anthropic()}") == ["SS016"]


def test_url_with_credentials():
    assert ids("curl https://deploy:Xk9mQ2vLp7zRt@example.org/api") == ["SS029"]
    assert ids("curl https://example.org/api") == []

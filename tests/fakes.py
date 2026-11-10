"""Fake credentials, assembled at runtime so no full token literal lives in the repository
(avoids tripping secret scanners and push protection). None of these are real."""

_ALPHA = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0xR"


def _fill(n: int, alphabet: str = _ALPHA) -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


def anthropic() -> str:
    return "sk-" + "ant-" + "api03-" + _fill(95, _ALPHA + "-_")


def openai() -> str:
    return "sk-" + "proj-" + _fill(48)


def slack_webhook() -> str:
    return "https://hooks." + "slack.com/services/" + "T01ABCDEF" + "/" + "B01ABCDEF" + "/" + _fill(24)


def discord_webhook() -> str:
    return "https://discord." + "com/api/webhooks/" + "1" * 18 + "/" + _fill(64)


def npm() -> str:
    return "npm" + "_" + _fill(36)


def gitlab() -> str:
    return "glpat" + "-" + _fill(20)


def pypi() -> str:
    return "pypi" + "-" + "AgEIcHlwaS5vcmc" + _fill(70)


def docker_pat() -> str:
    return "dckr" + "_pat_" + _fill(30)


def huggingface() -> str:
    return "hf" + "_" + "".join(c for c in _fill(60) if c.isalpha())[:34]


def twilio() -> str:
    return "SK" + "0123456789abcdef" * 2


def telegram() -> str:
    return "123456789" + ":AA" + _fill(33)


def azure_key() -> str:
    return "AccountKey" + "=" + _fill(86, _ALPHA + "+/") + "=="


def shopify() -> str:
    return "shp" + "at_" + "0123456789abcdef" * 2


def github_pat() -> str:
    return "ghp" + "_" + _fill(36)

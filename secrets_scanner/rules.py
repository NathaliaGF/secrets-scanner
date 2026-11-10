"""
Detection rules. Each rule is a compiled regex plus metadata.

secret_group: which capture group holds the secret value (0 = the whole match).
generic:      value is only identified by the name of the variable it is assigned to, so the
              match is filtered (placeholders, code expressions, entropy) before it is reported.
              Specific-format rules are precise enough that the pattern itself is the filter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    name: str
    pattern: re.Pattern
    detail: str
    fix: str
    secret_group: int = 0
    generic: bool = False
    min_len: int = 6
    min_entropy: float = 0.0
    mask: bool = True       # False when the match is only a marker (PEM header), not the secret


def _val(n: int) -> str:
    """Capture group for an assigned value: quoted (may contain spaces) or bare (.env / YAML)."""
    return (
        rf"""((?:(?<=")[^"\r\n]{{{n},}}(?=")|(?<=')[^'\r\n]{{{n},}}(?=')|[^\s"'`;,]{{{n},}}))"""
    )


# key, optional closing quote, separator (=, :, :=, =>), optional opening quote
_SEP = r"""["']?\s*(?:=>|:=|=|:)\s*["']?"""

_ENV_FIX = "Move the value to an environment variable or a secrets manager and rotate it."

RULES: list[Rule] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    Rule(
        "SS001", "CRITICAL", "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "An exposed AWS Access Key ID lets anyone make authenticated AWS calls, "
        "create resources and run up costs.",
        "Revoke the key in the AWS IAM console. Use IAM roles or environment variables instead.",
    ),
    Rule(
        "SS002", "CRITICAL", "AWS Secret Access Key",
        re.compile(
            r"aws[_-]?secret[_-]?(?:access[_-]?)?key" + _SEP + r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        "Combined with the Access Key ID, the secret key gives full access to the AWS account.",
        "Revoke the key pair in the AWS IAM console. Use AWS Secrets Manager or IAM roles.",
        secret_group=1,
    ),
    # ── GitHub ───────────────────────────────────────────────────────────────
    Rule(
        "SS003", "CRITICAL", "GitHub Personal Access Token (classic)",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "A classic PAT grants access to private repositories according to its scopes.",
        "Revoke it at github.com/settings/tokens. Use Actions secrets or environment variables in CI.",
    ),
    Rule(
        "SS004", "CRITICAL", "GitHub Fine-grained Token",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "A fine-grained token exposes the repositories and organisations it was issued for.",
        "Revoke it at github.com/settings/tokens and issue a new one stored in a secrets manager.",
    ),
    Rule(
        "SS005", "HIGH", "GitHub OAuth / App Token",
        re.compile(r"(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"),
        "OAuth and GitHub App tokens can expose user and organisation data.",
        "Revoke the token in the OAuth App / GitHub App settings and issue a new one.",
    ),
    # ── Google ───────────────────────────────────────────────────────────────
    Rule(
        "SS006", "HIGH", "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "A Google API key can be used to bill your project (Maps, Vision, Translate...) or leak data.",
        "Restrict the key by API and referrer/IP in Google Cloud, regenerate it and store it outside the code.",
    ),
    # ── Stripe ───────────────────────────────────────────────────────────────
    Rule(
        "SS007", "CRITICAL", "Stripe Secret / Restricted Key (live)",
        re.compile(r"[sr]k_live_[0-9a-zA-Z]{24,}"),
        "A live Stripe secret key can create charges and read customer data.",
        "Roll the key in the Stripe dashboard immediately and keep it server-side in an environment variable.",
    ),
    Rule(
        "SS008", "MEDIUM", "Stripe Publishable Key (live)",
        re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        "Publishable keys are semi-public, but finding one often means other Stripe secrets are nearby.",
        "Move it to configuration and check that the matching secret key is not exposed.",
    ),
    # ── Slack / Discord ──────────────────────────────────────────────────────
    Rule(
        "SS009", "HIGH", "Slack Token",
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        "A Slack token can read messages and post as the bot or user.",
        "Revoke it at api.slack.com/apps and load the new one from the environment.",
    ),
    Rule(
        "SS018", "HIGH", "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
        "Anyone with the webhook URL can post messages to your Slack channel.",
        "Regenerate the webhook in the Slack app settings and store the URL as a secret.",
    ),
    Rule(
        "SS019", "HIGH", "Discord Webhook URL",
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w\-]{60,}"),
        "Anyone with the webhook URL can post messages to your Discord channel.",
        "Delete and recreate the webhook in the channel settings and store the URL as a secret.",
    ),
    # ── Private keys ─────────────────────────────────────────────────────────
    Rule(
        "SS010", "CRITICAL", "Private key (RSA / EC / DSA / OpenSSH / PGP / PKCS#8)",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "A private key compromises every system that trusts the matching public key "
        "(SSH servers, TLS, signatures). GCP service-account JSON keys are caught here too.",
        "Revoke and regenerate the key pair. Never commit .pem / .key / id_rsa files; add them to .gitignore.",
        mask=False,
    ),
    # ── Connection strings ───────────────────────────────────────────────────
    Rule(
        "SS011", "CRITICAL", "Database / broker URL with credentials",
        re.compile(
            r"\b(?:mysql|mariadb|postgres(?:ql)?|mongodb|redis|rediss|amqps?|mssql|sqlserver)(?:\+\w+)?://"
            r"[^:@/\s]+:(?![$<{%])([^@\s]{3,})@",
            re.IGNORECASE,
        ),
        "A connection string with user and password gives direct access to the database or broker.",
        "Remove the credentials from the URL: DATABASE_URL=postgresql://user:${DB_PASS}@host/db",
        secret_group=1, generic=True,
    ),
    Rule(
        "SS027", "CRITICAL", "Azure Storage connection string key",
        re.compile(r"AccountKey=[A-Za-z0-9+/]{86}=="),
        "The account key gives full access to the Azure storage account.",
        "Rotate the storage account key in the Azure portal and use managed identities or Key Vault.",
    ),
    Rule(
        "SS029", "MEDIUM", "HTTP(S) URL with embedded credentials",
        re.compile(r"https?://[^/\s:@]+:(?![$<{%])([^/\s@]{3,})@", re.IGNORECASE),
        "Credentials embedded in a URL end up in logs, shell history and proxies.",
        "Use a token header or a credential helper instead of user:password@host.",
        secret_group=1, generic=True,
    ),
    # ── Tokens ───────────────────────────────────────────────────────────────
    Rule(
        "SS012", "MEDIUM", "JWT",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}"),
        "A leaked JWT can be replayed until it expires, and its payload may expose data.",
        "Never hard-code JWTs. Use short expirations and rotate tokens.",
    ),
    Rule(
        "SS013", "HIGH", "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
        "A SendGrid key lets an attacker send e-mail as you (spam, phishing).",
        "Revoke it at app.sendgrid.com/settings/api_keys and load the new one from the environment.",
    ),
    Rule(
        "SS016", "CRITICAL", "Anthropic API Key",
        re.compile(r"sk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_\-]{60,}"),
        "A leaked LLM API key lets others consume your quota and read what your workspace sends.",
        "Revoke it in the Anthropic console and load the new key from the environment.",
    ),
    Rule(
        "SS017", "CRITICAL", "OpenAI API Key",
        re.compile(r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_\-]{32,}\b"),
        "A leaked LLM API key lets others consume your quota.",
        "Revoke it in the OpenAI dashboard and load the new key from the environment.",
    ),
    Rule(
        "SS020", "HIGH", "npm Access Token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "An npm token can publish packages in your name (supply-chain risk).",
        "Revoke it at npmjs.com and use short-lived or granular tokens in CI.",
    ),
    Rule(
        "SS021", "HIGH", "GitLab Personal Access Token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
        "A GitLab PAT grants API access according to its scopes.",
        "Revoke it in your GitLab user settings and use CI/CD variables.",
    ),
    Rule(
        "SS022", "HIGH", "PyPI Upload Token",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
        "A PyPI token can publish releases in your name (supply-chain risk).",
        "Revoke it at pypi.org and use trusted publishing or a project-scoped token.",
    ),
    Rule(
        "SS023", "HIGH", "Docker Hub Personal Access Token",
        re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27,}"),
        "A Docker Hub PAT can pull private images and push over yours.",
        "Revoke it in Docker Hub security settings and store it as a CI secret.",
    ),
    Rule(
        "SS024", "HIGH", "Hugging Face Access Token",
        re.compile(r"\bhf_[A-Za-z]{34}\b"),
        "A Hugging Face token can read private models and datasets and write to your repos.",
        "Revoke it in your Hugging Face settings and load the new one from the environment.",
    ),
    Rule(
        "SS025", "HIGH", "Twilio API Key SID",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "A Twilio API key is used with its secret to send SMS and make calls on your account.",
        "Delete the key in the Twilio console and issue a new one stored outside the code.",
    ),
    Rule(
        "SS026", "HIGH", "Telegram Bot Token",
        re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"),
        "A bot token gives full control of the Telegram bot.",
        "Revoke it with BotFather (/revoke) and load the new token from the environment.",
    ),
    Rule(
        "SS028", "HIGH", "Shopify Access Token",
        re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
        "A Shopify token gives API access to the store.",
        "Rotate the token in the Shopify admin and store it as a secret.",
    ),
    # ── Generic assignments (filtered) ───────────────────────────────────────
    Rule(
        "SS014", "MEDIUM", "Hard-coded password",
        re.compile(
            r"(?i:(?:password|passwd|passphrase|(?<![a-z])pwd))" + _SEP + _val(8)
        ),
        "A hard-coded password is visible to everyone with access to the repository, "
        "forks and every copy of its history.",
        _ENV_FIX,
        secret_group=1, generic=True, min_len=8, min_entropy=2.5,
    ),
    Rule(
        "SS015", "MEDIUM", "Hard-coded API key / token",
        re.compile(
            r"(?i:(?:api[_-]?key|apikey|api[_-]?token|api[_-]?secret|secret[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|app[_-]?secret|private[_-]?key))" + _SEP + _val(20)
        ),
        "A hard-coded key or token gives access to an external service and stays in the Git history "
        "even after it is removed.",
        _ENV_FIX,
        secret_group=1, generic=True, min_len=20, min_entropy=3.2,
    ),
    Rule(
        "SS030", "MEDIUM", "High-entropy value in secret / token variable",
        re.compile(r"(?i:(?<![A-Za-z])(?:secret|token|credentials?))" + _SEP + _val(24)),
        "A long random value assigned to a variable named secret/token is very likely a credential.",
        _ENV_FIX,
        secret_group=1, generic=True, min_len=24, min_entropy=3.6,
    ),
]

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}

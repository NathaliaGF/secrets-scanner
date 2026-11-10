# secrets-scanner

[![CI](https://github.com/NathaliaGF/secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/NathaliaGF/secrets-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Find hard-coded secrets (API keys, tokens, passwords, private keys, connection strings) in files, directories, **staged changes** and **Git history**. Zero dependencies, SARIF output for GitHub Code Scanning, a ready-to-use GitHub Action and a pre-commit hook.

[Português](README.pt-BR.md)

## Why

A secret that was committed once lives in the Git history forever, even after the file is fixed. Most leaks are not exotic keys: they are `password=...` in a `.env` file, a connection string in a config, or a token pasted into a script. secrets-scanner catches those, reports where and when they entered, and is built to stay quiet on placeholders and code (`os.environ.get(...)`, `${DB_PASSWORD}`, `<your-token>`), so it is usable as a CI gate.

## Features

- **30 rules**: AWS, GitHub, GitLab, Google, Stripe, Slack, Discord, Azure, Twilio, Telegram, Shopify, npm, PyPI, Docker Hub, Hugging Face, Anthropic, OpenAI, SendGrid, JWT, private keys, database URLs, plus generic `password` / `api_key` / `token` assignments.
- **Understands config formats**: `KEY=value` in `.env`, `key: value` in YAML, JSON, and quoted code. Quoted values may contain spaces.
- **Git aware**: scans the history of every branch (`--git`) and reports a secret at the commit that introduced it, once. `--staged` scans only what you are about to commit.
- **Low noise**: placeholder, code-expression and entropy filters for generic rules; specific rules win over generic ones on the same value.
- **Safe output**: every secret on a line is masked, in the terminal, JSON and SARIF. Baselines store only truncated hashes.
- **CI ready**: SARIF 2.1.0, exit codes, severity threshold, baseline, GitHub Action, pre-commit hook.

## Install

```bash
pip install git+https://github.com/NathaliaGF/secrets-scanner.git
secrets-scanner --version
```

Or run it from a clone without installing: `python main.py --dir .`

## Usage

```bash
secrets-scanner --dir .                          # scan a directory
secrets-scanner --file .env                      # scan one file
secrets-scanner --dir . --git --max-commits 500  # also scan git history (0 = all commits)
secrets-scanner --staged                         # only what is staged (pre-commit)
secrets-scanner --dir . --severity HIGH          # report and fail only on HIGH or worse
secrets-scanner --dir . --output json            # machine-readable
secrets-scanner --dir . --output sarif --output-file results.sarif
secrets-scanner --list-rules
```

Example (`tests/samples/dirty.py`, all values are fake):

```text
secrets-scanner 1.0.0
Scope: tests/samples/dirty.py
Files scanned: 1
────────────────────────────────────────────────────────────────

📄 tests/samples/dirty.py
  🔴 [CRITICAL] SS001 AWS Access Key ID  (line 7)
     Code:   AWS_ACCESS_KEY_ID = "AKIA...MPLE"
     Secret: AKIA...MPLE
     Fix:    Revoke the key in the AWS IAM console. Use IAM roles or environment variables instead.
  🔴 [CRITICAL] SS011 Database / broker URL with credentials  (line 22)
     Code:   DATABASE_URL = "postgresql://admin:Supe...a123@db.example.com:5432/producao"
     Secret: Supe...a123
     Fix:    Remove the credentials from the URL: DATABASE_URL=postgresql://user:${DB_PASS}@host/db
  ...
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings (after severity filter, ignore rules and baseline) |
| 1 | findings |
| 2 | usage or runtime error (missing path, not a git repo, bad baseline) |

`--exit-zero` forces 0, useful to publish a report without failing the build.

## Silencing findings

1. **On one line**, with a comment: `password = "x"  # secrets-scanner:ignore` or only some rules: `# secrets-scanner:ignore SS014,SS015`.
2. **By path**, with a `.secretsignore` file in the scanned directory (or `--exclude PATTERN`, repeatable). One pattern per line, `#` for comments, `dir/` for directories, `*.md` for names, a pattern with `/` is anchored to the scan root. Negation (`!`) is not supported.
3. **By baseline**, to adopt the tool on an existing repository without fixing everything first:

```bash
secrets-scanner --dir . --update-baseline .secrets-baseline.json   # accept what exists today
secrets-scanner --dir . --baseline .secrets-baseline.json          # fail only on new findings
```

Rotate real secrets instead of baselining them.

## CI/CD

### GitHub Action

```yaml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write      # to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # needed for git-history
      - uses: NathaliaGF/secrets-scanner@main
        with:
          git-history: "true"
          severity: MEDIUM
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: secrets-scanner.sarif }
```

Inputs: `path`, `severity`, `git-history`, `max-commits`, `sarif-file`, `fail-on-findings`, `baseline`. This repository scans itself with this action (see `.github/workflows/ci.yml`).

### pre-commit

```yaml
repos:
  - repo: https://github.com/NathaliaGF/secrets-scanner
    rev: main
    hooks:
      - id: secrets-scanner
```

### GitLab CI

```yaml
secrets-scan:
  image: python:3.12
  script:
    - pip install git+https://github.com/NathaliaGF/secrets-scanner.git
    - secrets-scanner --dir . --output json --output-file secrets-report.json
  artifacts:
    when: always
    paths: [secrets-report.json]
```

## Rules

| ID | Severity | Detects |
|---|---|---|
| SS001 | CRITICAL | AWS Access Key ID |
| SS002 | CRITICAL | AWS Secret Access Key |
| SS003 | CRITICAL | GitHub Personal Access Token (classic) |
| SS004 | CRITICAL | GitHub Fine-grained Token |
| SS005 | HIGH | GitHub OAuth / App Token |
| SS006 | HIGH | Google API Key |
| SS007 | CRITICAL | Stripe Secret / Restricted Key (live) |
| SS008 | MEDIUM | Stripe Publishable Key (live) |
| SS009 | HIGH | Slack Token |
| SS010 | CRITICAL | Private key (RSA / EC / DSA / OpenSSH / PGP / PKCS#8) |
| SS011 | CRITICAL | Database / broker URL with credentials |
| SS012 | MEDIUM | JWT |
| SS013 | HIGH | SendGrid API Key |
| SS014 | MEDIUM | Hard-coded password |
| SS015 | MEDIUM | Hard-coded API key / token |
| SS016 | CRITICAL | Anthropic API Key |
| SS017 | CRITICAL | OpenAI API Key |
| SS018 | HIGH | Slack Webhook URL |
| SS019 | HIGH | Discord Webhook URL |
| SS020 | HIGH | npm Access Token |
| SS021 | HIGH | GitLab Personal Access Token |
| SS022 | HIGH | PyPI Upload Token |
| SS023 | HIGH | Docker Hub Personal Access Token |
| SS024 | HIGH | Hugging Face Access Token |
| SS025 | HIGH | Twilio API Key SID |
| SS026 | HIGH | Telegram Bot Token |
| SS027 | CRITICAL | Azure Storage connection string key |
| SS028 | HIGH | Shopify Access Token |
| SS029 | MEDIUM | HTTP(S) URL with embedded credentials |
| SS030 | MEDIUM | High-entropy value in secret / token variable |

Run `secrets-scanner --list-rules` for the same list. SS014, SS015, SS029, SS030 and the URL rules are *generic*: they identify a value by the name of the variable (or the URL shape), so they are filtered for placeholders, code expressions and entropy before being reported.

## How false positives are handled

For generic rules a value is **not** reported when it:

- is a placeholder: any word such as `your`, `example`, `changeme`, `dummy`, `fake`, `replace`, `todo`, `redacted`... as a whole token (so `Banana#Secure99` is still reported), or `xxxx`, `****`, a single repeated character;
- is code, not data: `os.environ.get(...)`, `get_password()`, `request.form[...]`, `${VAR}`, `{{ var }}`, `$(cmd)`, `<token>`;
- is a path or URL, or an unquoted identifier like `config.db_password`;
- is a type or keyword (`required`, `string`, `password: str`...);
- has too little entropy (thresholds per rule) or is shorter than the rule minimum.

Specific-format rules (AWS, GitHub, Stripe...) are precise enough that the pattern itself is the filter.

## Limitations

secrets-scanner is a **pattern scanner**, not a guarantee. A clean report does not mean a clean repository.

- **Generic rules can miss** secrets that look like words (`password: letmein`, below the entropy threshold), secrets built at runtime, or split across lines, and values in formats it does not parse (binary files, archives, images).
- **Generic rules can flag** non-secrets that look random and are named like secrets (hashes, test fixtures). Use the inline ignore, `.secretsignore` or a baseline.
- **Not scanned**: binary files, files larger than 1 MB (`--max-file-size`), lines longer than 2000 characters, lock files, `node_modules`, `venv` and similar directories. Skipped files are listed in the report.
- **History**: `--git` reads added lines of each commit's diff; it does not decode packed or encrypted blobs. Only the last `--max-commits` commits (default 100) are read; use `0` for all.
- **No online validation**: it does not check whether a found token is still active. Treat every finding as live and rotate it.
- A secret that reached a public remote must be considered compromised even if you rewrite history.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

The suite covers every rule (positive and negative cases), the regression cases from the first audit (unquoted `.env`/YAML values, PGP and encrypted keys, `--severity` exit code, masking of several secrets in one line), baseline, ignore files, SARIF/JSON shape, and git history/staged scans on temporary repositories. Fake credentials in the tests are assembled at runtime so no full token literal lives in the repository.

```text
secrets_scanner/
  rules.py          rule definitions (regex + metadata)
  file_scanner.py   line detection engine, file and directory scan, filters
  git_scanner.py    history and staged scan
  ignore.py         .secretsignore, --exclude, inline ignore
  baseline.py       baseline read/write
  report.py         terminal, JSON and SARIF output
  cli.py            command line
tests/
```

## License

MIT, see [LICENSE](LICENSE).

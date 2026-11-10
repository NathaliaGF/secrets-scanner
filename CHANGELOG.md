# Changelog

## 1.0.0

Rewrite after an audit that found real detection gaps.

### Fixed
- Secrets in **unquoted** assignments (`.env`, YAML, ini) were not detected by the generic rules.
- The placeholder filter dropped real passwords containing `na`, `abc`, `mock`, `sample`... inside a word. It now matches whole tokens.
- PGP (`... PRIVATE KEY BLOCK`) and `ENCRYPTED PRIVATE KEY` headers were not detected.
- `--severity` now means "this level or worse" and drives the exit code. Before, `--severity HIGH` with only MEDIUM findings still exited 1.
- A line with two secrets leaked the second one unmasked in the report of the first.
- AWS key ids are matched case-sensitively.
- README severities now match the code (GitHub tokens are CRITICAL).
- Unreadable and oversized files are reported instead of silently skipped.
- Git: a secret was reported once per commit that touched it, and again for the working tree.

### Added
- 15 rules (SS016-SS030): Anthropic, OpenAI, Slack/Discord webhooks, npm, GitLab, PyPI, Docker Hub, Hugging Face, Twilio, Telegram, Azure, Shopify, URL credentials, high-entropy secret/token variables.
- `--staged` and a pre-commit hook; SARIF 2.1.0 output; `--output-file`; `--baseline` / `--update-baseline`; `.secretsignore`, `--exclude` and inline `secrets-scanner:ignore`; `--max-file-size`; `--exit-zero`; `--list-rules`; `NO_COLOR`.
- Installable package (`pip install`, `secrets-scanner` command), GitHub Action, CI (Python 3.9-3.13 + self-scan).
- Tests grew from 84 to 200+, including git history and staged scans on temporary repositories.

### Changed
- Output and README in English (Portuguese README kept as `README.pt-BR.md`). No third-party dependencies (colorama removed).

# Secrets Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Testes](https://img.shields.io/badge/testes-84%20passando-brightgreen)
![Regras](https://img.shields.io/badge/regras-15-orange)
![Licença](https://img.shields.io/badge/licença-MIT-green)

CLI em Python que varre arquivos, diretórios e histórico Git em busca de segredos expostos — chaves de API, tokens, senhas, chaves privadas e URLs de banco de dados.

---

## Funcionalidades

- **15 regras** cobrindo os serviços mais comuns (AWS, GitHub, Stripe, Slack, Google, SendGrid…)
- **Varredura de histórico Git** — encontra segredos que já foram removidos do código mas ainda vivem nos commits
- **Filtragem de falsos positivos** via entropia de Shannon e detecção de placeholders
- **Saída em terminal colorida** (agrupada por arquivo) ou **JSON estruturado** para pipelines CI/CD
- **Código de saída `1`** quando encontrar segredos — integra nativamente com GitHub Actions, GitLab CI, etc.
- **Mascaramento automático** de segredos na saída (nunca expõe o valor completo)

---

## Regras implementadas

| ID | Severidade | O que detecta |
|----|-----------|---------------|
| SS001 | CRÍTICO | AWS Access Key ID (`AKIA…`) |
| SS002 | CRÍTICO | AWS Secret Access Key |
| SS003 | CRÍTICO | GitHub Personal Access Token (`ghp_…`) |
| SS004 | CRÍTICO | GitHub Fine-grained Token (`github_pat_…`) |
| SS005 | ALTO | GitHub OAuth / App Token (`gho_`, `ghs_`) |
| SS006 | ALTO | Google API Key (`AIza…`) |
| SS007 | CRÍTICO | Stripe Secret Key (`sk_live_…`) |
| SS008 | MÉDIO | Stripe Publishable Key (`pk_live_…`) |
| SS009 | ALTO | Slack Token (`xoxb-`, `xoxa-`, `xoxs-`) |
| SS010 | CRÍTICO | Chave privada PEM (`BEGIN … PRIVATE KEY`) |
| SS011 | CRÍTICO | URL de banco de dados com credenciais |
| SS012 | MÉDIO | JWT Token |
| SS013 | ALTO | SendGrid API Key (`SG.…`) |
| SS014 | MÉDIO | Senha em texto plano no código |
| SS015 | MÉDIO | Chave de API / token genérico |

---

## Instalação

```bash
git clone https://github.com/NathaliaGF/secrets-scanner.git
cd secrets-scanner
pip install -r requirements.txt
```

---

## Uso

### Varrer um arquivo

```bash
python main.py --file config.py
```

### Varrer um diretório inteiro

```bash
python main.py --dir ./meu-projeto
```

### Incluir histórico Git

```bash
python main.py --dir ./meu-projeto --git
```

### Filtrar por severidade mínima

```bash
python main.py --dir ./meu-projeto --severity HIGH
```

### Exportar resultado em JSON

```bash
python main.py --dir ./meu-projeto --output json > resultado.json
```

### Limitar commits escaneados

```bash
python main.py --dir ./meu-projeto --git --max-commits 200
```

---

## Exemplo de saída (terminal)

```
╔══════════════════════════════════════════════════════════════╗
║              SECRETS SCANNER — RELATÓRIO                     ║
╚══════════════════════════════════════════════════════════════╝

Arquivos varridos:  1
Segredos encontrados: 3
Nível de risco: CRÍTICO

──────────────────────────────────────────────────────────────
 config/settings.py
──────────────────────────────────────────────────────────────

 [SS001] CRÍTICO — AWS Access Key ID
  Linha 12: AWS_KEY = "AKIA...MPLE"
  Prévia:   AKIA...MPLE
  Correção: Remova a chave do código e use variáveis de ambiente

 [SS011] CRÍTICO — URL de banco de dados com credenciais
  Linha 24: DB = "postg...@loc..."
  Prévia:   post...5432
  Correção: Mova a URL de banco para variável de ambiente (DATABASE_URL)
```

---

## Exemplo de saída (JSON)

```json
{
  "summary": {
    "files_scanned": 1,
    "total_findings": 2,
    "risk_level": "CRÍTICO",
    "by_severity": { "CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 0 }
  },
  "findings": [
    {
      "rule_id": "SS001",
      "severity": "CRITICAL",
      "name": "AWS Access Key ID",
      "file": "config.py",
      "line": 12,
      "line_content": "AWS_KEY = \"AKIA...MPLE\"",
      "secret_preview": "AKIA...MPLE",
      "detail": "Chave de acesso AWS exposta permite acesso não autorizado à conta.",
      "fix": "Remova a chave do código e use variáveis de ambiente ou AWS Secrets Manager.",
      "commit": null
    }
  ]
}
```

---

## Integração com CI/CD

### GitHub Actions

```yaml
- name: Scan for secrets
  run: python main.py --dir . --severity HIGH
  # O job falha automaticamente se encontrar segredos (exit code 1)
```

### GitLab CI

```yaml
secrets-scan:
  script:
    - python main.py --dir . --output json > secrets-report.json
  artifacts:
    paths: [secrets-report.json]
```

---

## Testes

```bash
pytest tests/ -v
```

84 testes cobrindo todas as 15 regras, detecção de binários, filtragem de placeholders, entropia, mascaramento e varredura de diretórios.

---

## Estrutura do projeto

```
secrets-scanner/
├── main.py                    # Ponto de entrada CLI
├── requirements.txt
├── scanner/
│   ├── __init__.py            # Dataclass Finding
│   ├── rules.py               # 15 regras (SS001–SS015)
│   ├── file_scanner.py        # Varredura de arquivos e diretórios
│   ├── git_scanner.py         # Varredura de histórico Git
│   └── report.py              # Saída terminal e JSON
└── tests/
    ├── test_rules.py          # Testes unitários por regra
    ├── test_file_scanner.py   # Testes de helpers e integração
    └── samples/
        ├── dirty.py           # Arquivo com segredos reais falsos
        ├── clean.py           # Arquivo sem segredos
        ├── dirty.env          # .env com credenciais expostas
        └── clean.env          # .env seguro
```

---

## Roadmap

- [ ] Suporte a `.secretsignore` para excluir arquivos/padrões
- [ ] Integração com pre-commit hooks
- [ ] Relatório HTML
- [ ] Verificação online se tokens AWS/GitHub ainda são válidos
- [ ] Regras adicionais: Azure, GCP, Twilio, Datadog, NPM tokens

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

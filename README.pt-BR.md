# secrets-scanner

[![CI](https://github.com/NathaliaGF/secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/NathaliaGF/secrets-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Encontra segredos hard-coded (chaves de API, tokens, senhas, chaves privadas, strings de conexão) em arquivos, diretórios, **alterações em staging** e **histórico do Git**. Sem dependências, saída SARIF para o GitHub Code Scanning, GitHub Action pronta e hook de pre-commit.

[English](README.md)

## Por quê

Um segredo commitado uma vez fica no histórico do Git para sempre, mesmo depois de o arquivo ser corrigido. A maioria dos vazamentos não são chaves exóticas: é `password=...` num `.env`, uma string de conexão numa config, um token colado num script. O secrets-scanner pega isso, mostra onde e quando entrou, e foi feito para ficar quieto com placeholders e código (`os.environ.get(...)`, `${DB_PASSWORD}`, `<your-token>`), então serve como gate de CI.

## Recursos

- **30 regras**: AWS, GitHub, GitLab, Google, Stripe, Slack, Discord, Azure, Twilio, Telegram, Shopify, npm, PyPI, Docker Hub, Hugging Face, Anthropic, OpenAI, SendGrid, JWT, chaves privadas, URLs de banco, além de atribuições genéricas de `password` / `api_key` / `token`.
- **Entende formatos de configuração**: `KEY=valor` em `.env`, `chave: valor` em YAML, JSON e código com aspas. Valores entre aspas podem ter espaços.
- **Conhece o Git**: varre o histórico de todas as branches (`--git`) e reporta o segredo no commit que o introduziu, uma vez. `--staged` varre só o que você vai commitar.
- **Pouco ruído**: filtros de placeholder, de expressão de código e de entropia nas regras genéricas; regra específica vence a genérica no mesmo valor.
- **Saída segura**: todo segredo da linha é mascarado no terminal, JSON e SARIF. O baseline guarda só hashes truncados.
- **Pronto para CI**: SARIF 2.1.0, códigos de saída, severidade mínima, baseline, GitHub Action, hook de pre-commit.

## Instalação

```bash
pip install git+https://github.com/NathaliaGF/secrets-scanner.git
secrets-scanner --version
```

Ou, sem instalar, a partir de um clone: `python main.py --dir .`

## Uso

```bash
secrets-scanner --dir .                          # varre um diretório
secrets-scanner --file .env                      # varre um arquivo
secrets-scanner --dir . --git --max-commits 500  # inclui o histórico git (0 = todos os commits)
secrets-scanner --staged                         # só o que está em staging (pre-commit)
secrets-scanner --dir . --severity HIGH          # reporta e falha só de HIGH para cima
secrets-scanner --dir . --output json
secrets-scanner --dir . --output sarif --output-file results.sarif
secrets-scanner --list-rules
```

### Códigos de saída

| Código | Significado |
|---|---|
| 0 | nenhum achado (depois do filtro de severidade, ignores e baseline) |
| 1 | há achados |
| 2 | erro de uso ou execução (caminho inexistente, não é repositório git, baseline inválido) |

`--exit-zero` força 0, útil para publicar o relatório sem quebrar o build.

## Silenciar achados

1. **Numa linha**, com comentário: `password = "x"  # secrets-scanner:ignore` ou só algumas regras: `# secrets-scanner:ignore SS014,SS015`.
2. **Por caminho**, com um arquivo `.secretsignore` no diretório escaneado (ou `--exclude PADRÃO`, repetível). Um padrão por linha, `#` para comentário, `dir/` para diretórios, `*.md` para nomes; padrão com `/` é ancorado na raiz. Negação (`!`) não é suportada.
3. **Por baseline**, para adotar a ferramenta num repositório existente sem corrigir tudo antes:

```bash
secrets-scanner --dir . --update-baseline .secrets-baseline.json   # aceita o que existe hoje
secrets-scanner --dir . --baseline .secrets-baseline.json          # falha só em achados novos
```

Segredo real deve ser rotacionado, não colocado no baseline.

## CI/CD

### GitHub Action

```yaml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write      # para enviar o SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # necessário para git-history
      - uses: NathaliaGF/secrets-scanner@main
        with:
          git-history: "true"
          severity: MEDIUM
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: secrets-scanner.sarif }
```

Entradas: `path`, `severity`, `git-history`, `max-commits`, `sarif-file`, `fail-on-findings`, `baseline`. Este repositório se varre com essa action (veja `.github/workflows/ci.yml`).

### pre-commit

```yaml
repos:
  - repo: https://github.com/NathaliaGF/secrets-scanner
    rev: main
    hooks:
      - id: secrets-scanner
```

## Regras

Veja a tabela completa no [README em inglês](README.md#rules) ou rode `secrets-scanner --list-rules`. SS014, SS015, SS029, SS030 e as regras de URL são *genéricas*: identificam o valor pelo nome da variável (ou formato da URL) e por isso passam por filtros de placeholder, expressão de código e entropia.

## Limitações

O secrets-scanner é um **scanner por padrões**, não uma garantia. Relatório limpo não significa repositório limpo.

- **As regras genéricas podem deixar passar** segredos que parecem palavras (`password: letmein`, abaixo do limite de entropia), segredos montados em tempo de execução ou quebrados em várias linhas, e formatos que ele não lê (binários, arquivos compactados, imagens).
- **As regras genéricas podem alertar** valores que não são segredo mas parecem aleatórios e têm nome de segredo (hashes, fixtures de teste). Use o ignore inline, `.secretsignore` ou baseline.
- **Não são varridos**: binários, arquivos maiores que 1 MB (`--max-file-size`), linhas com mais de 2000 caracteres, lockfiles, `node_modules`, `venv` e similares. Os arquivos pulados aparecem no relatório.
- **Histórico**: `--git` lê as linhas adicionadas no diff de cada commit; não decodifica blobs compactados ou criptografados. Só os últimos `--max-commits` commits (padrão 100); use `0` para todos.
- **Sem validação online**: não confere se o token encontrado ainda está ativo. Trate todo achado como ativo e rotacione.
- Segredo que chegou a um remoto público deve ser considerado comprometido mesmo que você reescreva o histórico.

## Desenvolvimento

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

As credenciais falsas dos testes são montadas em tempo de execução, então nenhum token completo existe como texto no repositório.

## Licença

MIT, veja [LICENSE](LICENSE).

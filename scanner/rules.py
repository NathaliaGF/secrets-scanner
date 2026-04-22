"""
Secret detection rules — each rule contains a compiled regex and metadata.

secret_group: which capture group holds the actual secret value.
  0 → the full match IS the secret (e.g. AKIA...)
  1 → group 1 is the secret (e.g. password="<group1>")
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    name: str
    pattern: re.Pattern
    detail: str
    fix: str
    secret_group: int = 0   # regex group that contains the raw secret value
    entropy_check: bool = False  # apply Shannon-entropy filter (for generic rules)


RULES: list[Rule] = [

    # ── AWS ──────────────────────────────────────────────────────────────────

    Rule(
        id="SS001",
        severity="CRITICAL",
        name="AWS Access Key ID",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        detail=(
            "Uma AWS Access Key ID exposta permite que qualquer pessoa faça "
            "chamadas autenticadas à AWS em seu nome, podendo criar recursos e gerar custos."
        ),
        fix=(
            "Revogue a chave imediatamente em AWS IAM Console. "
            "Use variáveis de ambiente ou AWS IAM Roles em vez de credenciais hardcoded."
        ),
    ),

    Rule(
        id="SS002",
        severity="CRITICAL",
        name="AWS Secret Access Key",
        pattern=re.compile(
            r'(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            re.IGNORECASE,
        ),
        secret_group=1,
        detail=(
            "A AWS Secret Access Key combinada com o Access Key ID concede acesso "
            "completo à conta AWS. Nunca deve aparecer em código ou arquivos de configuração."
        ),
        fix=(
            "Revogue o par de chaves em AWS IAM Console. "
            "Use AWS Secrets Manager ou variáveis de ambiente para injetar credenciais."
        ),
    ),

    # ── GitHub ────────────────────────────────────────────────────────────────

    Rule(
        id="SS003",
        severity="HIGH",
        name="GitHub Personal Access Token (clássico)",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}"),
        detail=(
            "Um GitHub PAT permite acesso a repositórios privados, podendo clonar, "
            "fazer push e acessar dados da conta conforme os escopos concedidos."
        ),
        fix=(
            "Revogue o token em github.com/settings/tokens. "
            "Use GitHub Actions secrets ou variáveis de ambiente para CI/CD."
        ),
    ),

    Rule(
        id="SS004",
        severity="HIGH",
        name="GitHub Fine-grained Token",
        pattern=re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        detail=(
            "Token GitHub de granularidade fina exposto permite acesso controlado "
            "a repositórios e organizações específicas."
        ),
        fix=(
            "Revogue o token em github.com/settings/tokens e gere um novo. "
            "Armazene em variável de ambiente ou secrets manager."
        ),
    ),

    Rule(
        id="SS005",
        severity="HIGH",
        name="GitHub OAuth / App Token",
        pattern=re.compile(r"(?:gho|ghs|ghr)_[A-Za-z0-9]{36}"),
        detail=(
            "Token de OAuth ou GitHub App exposto pode comprometer integrações "
            "e conceder acesso indevido a dados de usuários ou organizações."
        ),
        fix="Revogue o token no painel do GitHub App ou OAuth App e gere um novo.",
    ),

    # ── Google ────────────────────────────────────────────────────────────────

    Rule(
        id="SS006",
        severity="HIGH",
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        detail=(
            "Uma Google API Key exposta pode ser usada para fazer chamadas em seu nome, "
            "gerando custos (Maps, Vision, Translation, etc.) ou vazando dados."
        ),
        fix=(
            "Restrinja a chave por IP e referrer no Google Cloud Console. "
            "Regenere-a e armazene em variável de ambiente."
        ),
    ),

    # ── Stripe ────────────────────────────────────────────────────────────────

    Rule(
        id="SS007",
        severity="CRITICAL",
        name="Stripe Secret Key (live)",
        pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        detail=(
            "A Stripe Secret Key de produção permite criar cobranças, acessar dados de "
            "clientes e realizar operações financeiras reais."
        ),
        fix=(
            "Revogue a chave no Stripe Dashboard imediatamente. "
            "Use variáveis de ambiente e nunca exponha a secret key no frontend."
        ),
    ),

    Rule(
        id="SS008",
        severity="MEDIUM",
        name="Stripe Publishable Key (live)",
        pattern=re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        detail=(
            "Embora a publishable key seja semi-pública, sua presença em código-fonte "
            "indica possível exposição de outras credenciais Stripe no mesmo arquivo."
        ),
        fix=(
            "Mova para variável de ambiente. Verifique se a secret key correspondente "
            "também não está exposta."
        ),
    ),

    # ── Slack ─────────────────────────────────────────────────────────────────

    Rule(
        id="SS009",
        severity="HIGH",
        name="Slack Bot / OAuth Token",
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        detail=(
            "Token Slack exposto permite ler mensagens, enviar conteúdo em nome do bot "
            "ou acessar dados de workspaces."
        ),
        fix=(
            "Revogue o token em api.slack.com/apps. "
            "Use variáveis de ambiente e nunca commite tokens Slack."
        ),
    ),

    # ── Chaves privadas ───────────────────────────────────────────────────────

    Rule(
        id="SS010",
        severity="CRITICAL",
        name="Chave privada (RSA / EC / SSH / PGP)",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        detail=(
            "Uma chave privada exposta compromete completamente qualquer sistema ou serviço "
            "que use a chave pública correspondente (servidores SSH, TLS, assinaturas)."
        ),
        fix=(
            "Revogue e regenere o par de chaves imediatamente. "
            "Nunca adicione arquivos .pem, .key ou id_rsa ao repositório — use .gitignore."
        ),
    ),

    # ── Banco de dados ────────────────────────────────────────────────────────

    Rule(
        id="SS011",
        severity="CRITICAL",
        name="URL de banco de dados com credenciais",
        pattern=re.compile(
            r"(?:mysql|postgresql|postgres|mongodb|redis|amqp)(?:\+\w+)?://"
            r"[^:@\s]{1,}:[^@\s]{3,}@",
            re.IGNORECASE,
        ),
        detail=(
            "Uma connection string com usuário e senha exposta dá acesso direto "
            "ao banco de dados, podendo vazar ou destruir todos os dados."
        ),
        fix=(
            "Remova as credenciais da URL. Use variáveis de ambiente: "
            "DATABASE_URL=postgresql://user:${DB_PASS}@host/db"
        ),
    ),

    # ── JWT ───────────────────────────────────────────────────────────────────

    Rule(
        id="SS012",
        severity="MEDIUM",
        name="JWT Token",
        pattern=re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-\+/=]{10,}"
        ),
        detail=(
            "Um JWT exposto pode ser reutilizado para autenticação enquanto estiver válido. "
            "JWTs com dados sensíveis no payload também vazam informações."
        ),
        fix=(
            "Nunca hardcode JWTs. Use expiração curta, rotação de tokens e "
            "armazene apenas no lado do servidor ou em cookies HttpOnly."
        ),
    ),

    # ── SendGrid ──────────────────────────────────────────────────────────────

    Rule(
        id="SS013",
        severity="HIGH",
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
        detail=(
            "Uma SendGrid API Key exposta permite enviar e-mails em seu nome, "
            "podendo ser usada para spam ou phishing."
        ),
        fix="Revogue a chave em app.sendgrid.com/settings/api_keys e use variável de ambiente.",
    ),

    # ── Genéricos (com filtro de entropia) ────────────────────────────────────

    Rule(
        id="SS014",
        severity="MEDIUM",
        name="Senha em texto plano no código",
        pattern=re.compile(
            r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]',
            re.IGNORECASE,
        ),
        secret_group=1,
        entropy_check=True,
        detail=(
            "Senha hardcoded em código-fonte é visível para qualquer pessoa com acesso "
            "ao repositório, incluindo colaboradores, forks e vazamentos de código."
        ),
        fix=(
            "Use variáveis de ambiente (os.environ) ou um secrets manager. "
            "Nunca escreva senhas diretamente no código."
        ),
    ),

    Rule(
        id="SS015",
        severity="MEDIUM",
        name="API Key / Token / Secret genérico",
        pattern=re.compile(
            r'(?:api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token)'
            r'\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]',
            re.IGNORECASE,
        ),
        secret_group=1,
        entropy_check=True,
        detail=(
            "Uma chave ou token genérico hardcoded pode dar acesso a APIs externas "
            "e é persistido no histórico do git mesmo após ser removido."
        ),
        fix=(
            "Mova o valor para uma variável de ambiente e acesse via os.environ.get(). "
            "Adicione .env ao .gitignore."
        ),
    ),
]

# Lookup por ID para acesso rápido nos testes
RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}

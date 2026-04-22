# ✅ Arquivo limpo — usa boas práticas, sem segredos hardcoded.

import os

# Credenciais lidas de variáveis de ambiente
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
GITHUB_TOKEN          = os.environ.get("GITHUB_TOKEN")
GOOGLE_API_KEY        = os.environ.get("GOOGLE_API_KEY")
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY")
DATABASE_URL          = os.environ.get("DATABASE_URL")

# Valores placeholder (não são segredos reais)
API_KEY    = "your-api-key-here"
SECRET     = "changeme"
PASSWORD   = "example-password"
TOKEN      = "xxx"

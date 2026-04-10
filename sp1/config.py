# =============================================================
# GID Lab - Grupo 4 | SP1 Vulnerability Configuration
# =============================================================
# Flags de controlo das vulnerabilidades.
# True  = sistema VULNERÁVEL (para demonstração do ataque)
# False = mitigação ATIVA
# =============================================================

# A-06 | Token Leakage via Referrer Header
# Quando True: o access_token é colocado na URL do dashboard
# e a página carrega um recurso externo (attacker server).
# O browser envia automaticamente o header Referer com o token.
VULN_A06_REFERRER_LEAK = False

# A-09 | Session Fixation after SSO
# Quando True: o session ID NÃO é regenerado após login bem-sucedido.
# Permite que um atacante que fixou o session ID ganhe acesso autenticado.
VULN_A09_NO_SESSION_REGEN = False

# A-07 | Open Redirector
# Quando True: o parâmetro 'next' não é validado.
# Permite redirecionar o utilizador para qualquer URL externa após login.
VULN_A07_OPEN_REDIRECT = False

# =============================================================
# Configurações fixas do SP1
# =============================================================
KEYCLOAK_BASE     = "http://localhost:8080"
KEYCLOAK_REALM    = "gid-lab"
CLIENT_ID         = "sp1-client"
CLIENT_SECRET     = "sp1-secret-gid2026"
SP1_BASE_URL      = "http://localhost:5001"
ATTACKER_BASE_URL = "http://localhost:9999"

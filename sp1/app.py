"""
GID Lab - Grupo 4
SP1: Portal A (Service Provider 1)
Porta: 5001

Vulnerabilidades intencionais (controladas por config.py):
  A-06: Token na URL → recurso externo → Referer header leaks token
  A-09: Session Fixation → session ID não é regenerado após login
  A-07: Open Redirect → parâmetro 'next' não é validado
"""

import os
from flask import Flask, redirect, url_for, session, request, render_template
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from config import *

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "sp1-super-secret-key-gid2026-change-in-prod"

# Sessões server-side (filesystem) — necessário para demo A-09
os.makedirs("./flask_session", exist_ok=True)
app.config["SESSION_TYPE"]            = "filesystem"
app.config["SESSION_FILE_DIR"]        = "./flask_session"
app.config["SESSION_COOKIE_NAME"]     = "sp1_session"
app.config["SESSION_COOKIE_HTTPONLY"] = False   # A-09 VULN: permite injecção via JS (document.cookie)
# A-09 VULN: SameSite=Lax permite que o cookie seja enviado em cross-site requests
# MITIGAÇÃO seria SameSite=Strict
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

Session(app)

# ------------------------------------------------------------------
# OIDC / OAuth2 via Keycloak
# ------------------------------------------------------------------
oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}"
        f"/.well-known/openid-configuration"
    ),
    client_kwargs={"scope": "openid profile email roles"},
)


# ------------------------------------------------------------------
# Helper: verificar autenticação
# ------------------------------------------------------------------
def current_user():
    return session.get("user")

def require_login():
    """Retorna redirect para login se não autenticado, None se OK."""
    if not current_user():
        return redirect(url_for("login"))
    return None


# ------------------------------------------------------------------
# Rotas
# ------------------------------------------------------------------

@app.route("/")
def index():
    user = current_user()
    if not user:
        return render_template("landing.html")
    return render_template("home.html", user=user)


@app.route("/login")
def login():
    """
    [A-07 VULN] O parâmetro 'next' é guardado na sessão sem validação.
    Qualquer URL externa pode ser usada: ?next=http://evil.com
    """
    next_url = request.args.get("next", "")
    if VULN_A07_OPEN_REDIRECT:
        session["next_url"] = next_url          # VULN: sem validação
    else:
        # MITIGAÇÃO: apenas paths internos são permitidos
        if next_url.startswith("/") and not next_url.startswith("//"):
            session["next_url"] = next_url
        else:
            session["next_url"] = ""

    redirect_uri = url_for("callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    """
    [A-06 VULN] Após trocar o code por token, o access_token é passado
                na URL de redirect para o dashboard. Qualquer recurso
                externo nessa página recebe o token via header Referer.

    [A-09 VULN] O session ID NÃO é regenerado após login.
                Um atacante que fixou o session ID antes do login
                fica automaticamente autenticado.

    [A-07 VULN] Redireciona para 'next_url' sem validar se é interno.
    """
    # Troca o authorization code por tokens junto do Keycloak
    token = oauth.keycloak.authorize_access_token()
    user_info = token.get("userinfo")

    # ---- A-09: Session Fixation ----
    if VULN_A09_NO_SESSION_REGEN:
        # VULN: mantém o mesmo session ID — o atacante que fixou este ID
        # fica agora autenticado com os dados do utilizador legítimo
        pass
    else:
        # MITIGAÇÃO: session.clear() sozinho não chega — mantém o mesmo ID.
        # É necessário gerar um novo SID e abandonar o antigo.
        import secrets
        session.clear()
        session.sid = secrets.token_urlsafe(32)

    # Guardar dados do utilizador na sessão
    session["user"]         = user_info
    session["access_token"] = token.get("access_token")

    # ---- A-07: Open Redirect ----
    next_url = session.pop("next_url", "")
    if VULN_A07_OPEN_REDIRECT and next_url:
        # VULN: redireciona para qualquer URL sem verificar se é interna
        return redirect(next_url)

    # ---- A-06: Token in URL ----
    if VULN_A06_REFERRER_LEAK:
        # VULN: passa o access_token como query parameter na URL
        # A página de dashboard carrega recursos do attacker server
        # → o browser envia Referer: http://localhost:5001/dashboard?token=...
        access_token = token.get("access_token")
        return redirect(url_for("dashboard", token=access_token))

    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    """
    [A-06 VULN] Esta página recebe o token na URL (?token=...) e carrega
                um recurso do attacker server. O browser envia o header
                Referer com a URL completa (incluindo o token).
    """
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    token_in_url = request.args.get("token", "")

    return render_template(
        "home.html",
        user=user,
        token_in_url=token_in_url,
        vuln_a06=VULN_A06_REFERRER_LEAK,
        attacker_url=ATTACKER_BASE_URL,
    )


@app.route("/admin")
def admin():
    """Área restrita — apenas utilizadores com role 'admin'."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    roles = user.get("roles", [])
    if "admin" not in roles:
        return render_template("error.html",
                               message="Acesso negado: é necessário o role 'admin'."), 403

    return render_template("admin.html", user=user)


@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    access_token = session.get("access_token", "")
    return render_template("profile.html", user=user, access_token=access_token)


@app.route("/logout")
def logout():
    session.clear()
    # Single Logout: terminar sessão também no Keycloak
    logout_url = (
        f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/logout"
        f"?post_logout_redirect_uri={SP1_BASE_URL}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)

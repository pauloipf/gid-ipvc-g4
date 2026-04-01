"""
GID Lab - Grupo 4
SP2: Portal B (Service Provider 2)
Porta: 5002

Demonstra SSO: se o utilizador já autenticou no SP1 (Portal A),
ao aceder ao SP2 o Keycloak reconhece a sessão activa e faz
login automático — sem mostrar o formulário de credenciais.
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
app.secret_key = "sp2-super-secret-key-gid2026-change-in-prod"

os.makedirs("./flask_session", exist_ok=True)
app.config["SESSION_TYPE"]            = "filesystem"
app.config["SESSION_FILE_DIR"]        = "./flask_session"
app.config["SESSION_COOKIE_NAME"]     = "sp2_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
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
# Rotas
# ------------------------------------------------------------------

@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("home.html", user=session["user"])


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()
    session.clear()
    session["user"]         = token.get("userinfo")
    session["access_token"] = token.get("access_token")
    return redirect(url_for("index"))


@app.route("/admin")
def admin():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    if "admin" not in user.get("roles", []):
        return render_template("error.html",
                               message="Acesso negado: role 'admin' necessário."), 403
    return render_template("admin.html", user=user)


@app.route("/profile")
def profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    return render_template("profile.html",
                           user=user,
                           access_token=session.get("access_token", ""))


@app.route("/logout")
def logout():
    session.clear()
    logout_url = (
        f"{KEYCLOAK_BASE}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/logout"
        f"?post_logout_redirect_uri={SP2_BASE_URL}"
        f"&client_id={CLIENT_ID}"
    )
    return redirect(logout_url)


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)

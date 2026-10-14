#!/usr/bin/env python3
"""
app_insegura.py - Portal do Gerente (RP/cliente OIDC) COM FALHAS DE PROPOSITO.
Use SOMENTE no laboratorio. Cada falha esta marcada com  # FALHA n.
"""
import os

import jwt
import requests
from flask import Flask, redirect, request, session

IDP = os.environ.get("IDP_URL", "http://localhost:9000")
CLIENT_ID = "portal-gerente"
CLIENT_SECRET = "segredo-do-portal-gerente-lab"          # FALHA 1: segredo no codigo-fonte
REDIRECT_URI = os.environ.get("RP_REDIRECT", "http://localhost:5001/callback")


def criar_app():
    app = Flask("portal_inseguro")
    app.secret_key = "dev"                                  # FALHA 2: chave de sessao fraca/fixa
    app.config["SESSION_COOKIE_SECURE"] = False             # FALHA 3: cookie sem Secure
    app.config["SESSION_COOKIE_HTTPONLY"] = False           # FALHA 4: legivel por JavaScript

    @app.get("/login")
    def login():
        # FALHA 5: sem 'state' (CSRF de login) e sem 'nonce' (replay) e sem PKCE
        url = (f"{IDP}/authorize?response_type=code&client_id={CLIENT_ID}"
               f"&redirect_uri={REDIRECT_URI}&scope=openid%20profile%20email")
        session["next"] = request.args.get("next", "/")     # FALHA 6: aceita qualquer destino
        return redirect(url)

    @app.get("/callback")
    def callback():
        code = request.args.get("code")                     # FALHA 5 (cont.): nao confere state
        r = requests.post(f"{IDP}/token", data={            # FALHA 7: sem timeout
            "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT_URI})
        id_token = r.json()["id_token"]
        claims = jwt.decode(id_token, options={"verify_signature": False})   # FALHA 8: nao valida assinatura/iss/aud/exp
        session["user"] = claims["preferred_username"]       # FALHA 9: nao regenera sessao
        session["roles"] = claims.get("roles", [])
        app.logger.warning("login ok id_token=%s", id_token)      # FALHA 10: token em log
        return redirect(session.pop("next", "/"))            # FALHA 6 (cont.): open redirect

    @app.get("/")
    def home():
        return {"usuario": session.get("user"), "papeis": session.get("roles", [])}

    @app.get("/api/me")
    def api_me():
        tok = request.headers.get("Authorization", "")[7:]
        claims = jwt.decode(tok, options={"verify_signature": False})   # FALHA 8 (cont.): API confia no token sem validar
        return {"sub": claims["sub"], "roles": claims.get("roles", [])}

    @app.get("/gerencia/limites")
    def limites():
        if "gerente" not in session.get("roles", []):
            return {"erro": "acesso negado"}, 403
        return {"limite_pix_noturno": 1000, "usuario": session["user"]}

    return app


if __name__ == "__main__":
    criar_app().run(port=5001, debug=True)                    # FALHA 11: debug=True (console Werkzeug)

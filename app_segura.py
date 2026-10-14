#!/usr/bin/env python3
"""
app_segura.py - Portal do Gerente (RP/cliente OIDC) com as defesas corretas:
state + nonce + PKCE(S256), validacao completa do ID Token via JWKS, redirect interno,
segredos por ambiente, cookies enderecados, sessao regenerada, timeouts, MFA 'step-up' (acr).
"""
import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode, urlparse

import requests
from flask import Flask, abort, redirect, request, session

from jwt_validator import TokenInvalido, validar_seguro

IDP = os.environ.get("IDP_URL", "http://localhost:9000")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "portal-gerente")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")           # vem do ambiente/cofre
REDIRECT_URI = os.environ.get("RP_REDIRECT", "http://localhost:5002/callback")
HTTP_TIMEOUT = (3, 5)                                               # (conexao, leitura) em segundos


def _pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _destino_seguro(destino: str) -> str:
    """Somente caminhos RELATIVOS internos. Bloqueia //evil.com, http://evil.com, \\\\evil.com etc."""
    if not destino or not destino.startswith("/") or destino.startswith("//") or "\\" in destino:
        return "/"
    p = urlparse(destino)
    return destino if not p.scheme and not p.netloc else "/"


def criar_app(secure_cookies: bool = True):
    app = Flask("portal_seguro")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_SECURE=secure_cookies, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=900)
    cache = {"jwks": None, "t": 0.0}

    def jwks():
        if not cache["jwks"] or time.time() - cache["t"] > 300:
            cfg = requests.get(f"{IDP}/.well-known/openid-configuration", timeout=HTTP_TIMEOUT).json()
            cache["jwks"] = requests.get(cfg["jwks_uri"], timeout=HTTP_TIMEOUT).json()
            cache["t"] = time.time()
        return cache["jwks"]

    @app.get("/login")
    def login():
        verifier, challenge = _pkce()
        session.clear()
        session["state"], session["nonce"], session["verifier"] = (
            secrets.token_urlsafe(24), secrets.token_urlsafe(24), verifier)
        session["next"] = _destino_seguro(request.args.get("next", "/"))
        q = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
             "scope": "openid profile email", "state": session["state"], "nonce": session["nonce"],
             "code_challenge": challenge, "code_challenge_method": "S256"}
        return redirect(f"{IDP}/authorize?{urlencode(q)}")

    @app.get("/callback")
    def callback():
        if request.args.get("error"):
            abort(401)
        if not secrets.compare_digest(request.args.get("state", ""), session.get("state", "-")):
            abort(400, "state invalido")                           # barra CSRF de login
        code, verifier, nonce = request.args.get("code"), session.get("verifier"), session.get("nonce")
        destino = session.get("next", "/")
        if not code or not verifier:
            abort(400)
        try:
            r = requests.post(f"{IDP}/token", timeout=HTTP_TIMEOUT, data={
                "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET, "redirect_uri": REDIRECT_URI, "code_verifier": verifier})
        except requests.RequestException:
            abort(503)                                               # IdP fora do ar: falha FECHADA, sem erro 500
        if r.status_code != 200:
            abort(401)
        try:
            claims = validar_seguro(r.json()["id_token"], jwks, issuer=IDP, audience=CLIENT_ID, nonce=nonce)
        except TokenInvalido as e:
            app.logger.warning("id_token rejeitado: %s", e)         # loga o MOTIVO, nunca o token
            abort(401)
        except requests.RequestException:
            abort(503)                                               # IdP fora do ar: falha FECHADA
        session.clear()                                              # nova sessao pos-login (anti fixation)
        session.permanent = True
        session.update(user=claims["preferred_username"], roles=claims.get("roles", []),
                       acr=claims.get("acr", "0"), amr=claims.get("amr", []), login_em=int(time.time()))
        return redirect(destino)

    @app.get("/")
    def home():
        return {"usuario": session.get("user"), "papeis": session.get("roles", [])}

    @app.get("/api/me")
    def api_me():
        tok = request.headers.get("Authorization", "")[7:]
        try:
            c = validar_seguro(tok, jwks, issuer=IDP, audience="api-contas")   # access token: aud = API
        except TokenInvalido:
            abort(401)
        except requests.RequestException:
            abort(503)
        return {"sub": c["sub"]}

    @app.get("/gerencia/limites")
    def limites():
        if "gerente" not in session.get("roles", []):
            return {"erro": "acesso negado"}, 403
        if session.get("acr") != "2":                                # step-up: operacao critica exige MFA
            return {"erro": "mfa_necessario"}, 401
        return {"limite_pix_noturno": 1000, "usuario": session["user"]}

    return app


if __name__ == "__main__":
    criar_app(secure_cookies=False).run(port=5002, debug=False)     # Secure=False so p/ HTTP local do lab

#!/usr/bin/env python3
"""
mini_idp.py - Provedor de identidade OIDC minimo (didatico) com Authorization Code + PKCE + MFA TOTP.

NAO e produto. Serve para a turma VER cada passo do protocolo funcionando na propria VM Debian,
sem depender de Keycloak/Docker. Para producao: Keycloak, Authentik, Dex, Zitadel etc.

Endpoints
  GET  /.well-known/openid-configuration   (discovery)
  GET  /jwks                               (chaves publicas de assinatura)
  GET  /authorize                          (formulario de login)  | POST /authorize (login + MFA)
  POST /token                              (troca code -> tokens)
  GET  /userinfo                           (claims do usuario, Bearer)
  GET  /logout                             (RP-initiated logout simplificado)

Execucao:  python3 mini_idp.py            (porta 9000)
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, redirect, request
from markupsafe import escape

import totp
from jwt_validator import jwks_de

ISSUER = os.environ.get("IDP_ISSUER", "http://localhost:9000")
KID = "mini-idp-2025-01"
CODE_TTL = 60            # authorization code vale 60 s e e de uso unico
ID_TOKEN_TTL = 300
ACCESS_TOKEN_TTL = 300


def _hash_senha(senha: str, sal: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), sal, 200_000)


def _mk_user(nome, senha, papeis, grupos, otp_secret=None, email=None):
    sal = secrets.token_bytes(16)
    return {"sub": nome, "preferred_username": nome, "email": email or f"{nome}@banco.exemplo",
            "roles": papeis, "groups": grupos, "salt": sal, "hash": _hash_senha(senha, sal),
            "otp_secret": otp_secret}


class Estado:
    """Todo o estado do IdP em memoria (reiniciou, zerou)."""

    def __init__(self):
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwks = jwks_de(self.priv.public_key(), KID)
        self.codes: dict[str, dict] = {}
        self.otp = totp.VerificadorTOTP()
        self.falhas: dict[str, list[float]] = {}
        self.clientes = {
            "portal-gerente": {"secret": "segredo-do-portal-gerente-lab",
                               "redirect_uris": ["http://localhost:5001/callback",
                                                 "http://localhost:5002/callback"],
                               "publico": False, "exige_pkce": False},
            "app-mobile": {"secret": None, "redirect_uris": ["http://localhost:5003/callback"],
                           "publico": True, "exige_pkce": True},
        }
        self.otp_ana = totp.novo_segredo()
        self.usuarios = {
            "ana.silva": _mk_user("ana.silva", "Senha-Forte-Lab#1", ["gerente"], ["agencia-centro"],
                                  otp_secret=self.otp_ana),
            "joao.atendente": _mk_user("joao.atendente", "Senha-Forte-Lab#2", ["atendente"],
                                       ["agencia-centro"], otp_secret=None),
        }


def criar_app(estado: Estado | None = None, exigir_mfa: bool = True) -> Flask:
    app = Flask("mini_idp")
    E = estado or Estado()
    app.estado = E                      # type: ignore[attr-defined]

    # ----- discovery e JWKS -----------------------------------------------------------
    @app.get("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/jwks",
            "end_session_endpoint": f"{ISSUER}/logout",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "auth_time", "amr",
                                 "acr", "preferred_username", "email", "roles", "groups"],
        })

    @app.get("/jwks")
    def jwks():
        return jsonify(E.jwks)

    # ----- /authorize -------------------------------------------------------------------
    def _validar_requisicao(args):
        c = E.clientes.get(args.get("client_id", ""))
        if not c:
            return None, "client_id desconhecido"
        ru = args.get("redirect_uri", "")
        if ru not in c["redirect_uris"]:                      # comparacao EXATA, sem prefixo/wildcard
            return None, "redirect_uri nao registrada"
        return c, None

    def _erro_redirect(ru, state, erro):
        q = {"error": erro}
        if state:
            q["state"] = state
        return redirect(f"{ru}?{urlencode(q)}", 302)

    @app.get("/authorize")
    def authorize_get():
        c, err = _validar_requisicao(request.args)
        if err:
            return err, 400                                   # NUNCA redirecionar para URI nao validada
        a = request.args
        if a.get("response_type") != "code":
            return _erro_redirect(a["redirect_uri"], a.get("state"), "unsupported_response_type")
        if "openid" not in a.get("scope", "").split():
            return _erro_redirect(a["redirect_uri"], a.get("state"), "invalid_scope")
        if c["exige_pkce"] and not a.get("code_challenge"):
            return _erro_redirect(a["redirect_uri"], a.get("state"), "invalid_request")
        if a.get("code_challenge") and a.get("code_challenge_method") != "S256":
            return _erro_redirect(a["redirect_uri"], a.get("state"), "invalid_request")
        campos = "".join(f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">'
                         for k, v in a.items() if k.replace("_", "").isalnum())
        return ('<form method="post"><h3>Banco Exemplo - Login (IdP de laboratorio)</h3>'
                f'{campos}Usuario <input name="username"><br>Senha <input name="password" type="password"><br>'
                'Codigo MFA <input name="otp"><br><button>Entrar</button></form>')

    def _bloqueado(user):
        agora = time.time()
        E.falhas[user] = [t for t in E.falhas.get(user, []) if agora - t < 300]
        return len(E.falhas[user]) >= 5                        # 5 falhas / 5 min -> bloqueio temporario

    @app.post("/authorize")
    def authorize_post():
        f = request.form
        c, err = _validar_requisicao(f)
        if err:
            return err, 400
        state = f.get("state")
        user = E.usuarios.get(f.get("username", ""))
        nome = f.get("username", "")
        if _bloqueado(nome):
            return "conta temporariamente bloqueada", 429
        senha_ok = False
        if user:
            senha_ok = hmac.compare_digest(user["hash"], _hash_senha(f.get("password", ""), user["salt"]))
        else:
            _hash_senha("x", b"0" * 16)                         # equaliza tempo p/ nao revelar usuario
        amr = ["pwd"]
        if senha_ok and user["otp_secret"]:
            if not E.otp.verificar(nome, user["otp_secret"], f.get("otp", "")):
                senha_ok = False
            else:
                amr.append("otp")
        elif senha_ok and exigir_mfa and "gerente" in user["roles"]:
            senha_ok = False                                    # papel privilegiado sem MFA cadastrado
        if not senha_ok:
            E.falhas.setdefault(nome, []).append(time.time())
            return "credenciais invalidas", 401                 # mensagem unica: nao diz se foi senha ou OTP
        code = secrets.token_urlsafe(32)
        E.codes[code] = {"client_id": f["client_id"], "redirect_uri": f["redirect_uri"],
                         "nonce": f.get("nonce"), "user": user["sub"], "amr": amr,
                         "challenge": f.get("code_challenge"), "exp": time.time() + CODE_TTL,
                         "auth_time": int(time.time())}
        q = {"code": code}
        if state:
            q["state"] = state
        return redirect(f"{f['redirect_uri']}?{urlencode(q)}", 302)

    # ----- /token -----------------------------------------------------------------------
    def _erro_token(msg, status=400):
        r = jsonify({"error": msg})
        r.status_code = status
        r.headers["Cache-Control"] = "no-store"
        return r

    @app.post("/token")
    def token():
        f = request.form
        if f.get("grant_type") != "authorization_code":
            return _erro_token("unsupported_grant_type")
        c = E.clientes.get(f.get("client_id", ""))
        if not c:
            return _erro_token("invalid_client", 401)
        if not c["publico"] and not hmac.compare_digest(c["secret"], f.get("client_secret", "")):
            return _erro_token("invalid_client", 401)
        dados = E.codes.pop(f.get("code", ""), None)            # pop = USO UNICO
        if not dados or dados["exp"] < time.time():
            return _erro_token("invalid_grant")
        if dados["client_id"] != f["client_id"] or dados["redirect_uri"] != f.get("redirect_uri"):
            return _erro_token("invalid_grant")
        if dados["challenge"]:                                   # PKCE (RFC 7636)
            v = f.get("code_verifier", "")
            calc = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
            if not hmac.compare_digest(calc, dados["challenge"]):
                return _erro_token("invalid_grant")
        elif c["exige_pkce"]:
            return _erro_token("invalid_grant")
        u = E.usuarios[dados["user"]]
        agora = int(time.time())
        id_claims = {"iss": ISSUER, "sub": u["sub"], "aud": f["client_id"], "iat": agora,
                     "exp": agora + ID_TOKEN_TTL, "auth_time": dados["auth_time"],
                     "amr": dados["amr"], "acr": "2" if "otp" in dados["amr"] else "1",
                     "preferred_username": u["preferred_username"], "email": u["email"],
                     "roles": u["roles"], "groups": u["groups"]}
        if dados["nonce"]:
            id_claims["nonce"] = dados["nonce"]
        acc = {"iss": ISSUER, "sub": u["sub"], "aud": "api-contas", "azp": f["client_id"],
               "iat": agora, "exp": agora + ACCESS_TOKEN_TTL, "scope": "openid profile email",
               "jti": secrets.token_hex(8)}
        hdr = {"kid": KID, "typ": "JWT"}
        resp = jsonify({"token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL,
                        "id_token": jwt.encode(id_claims, E.priv, "RS256", headers=hdr),
                        "access_token": jwt.encode(acc, E.priv, "RS256", headers=hdr)})
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        return resp

    # ----- /userinfo --------------------------------------------------------------------
    @app.get("/userinfo")
    def userinfo():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "invalid_token"}), 401
        try:
            claims = jwt.decode(auth[7:], E.priv.public_key(), algorithms=["RS256"],
                                audience="api-contas", issuer=ISSUER)
        except jwt.PyJWTError:
            return jsonify({"error": "invalid_token"}), 401
        u = E.usuarios[claims["sub"]]
        return jsonify({k: u[k] for k in ("sub", "preferred_username", "email", "roles", "groups")})

    @app.get("/logout")
    def logout():
        return jsonify({"status": "sessao do IdP encerrada (simulado)"})

    return app


if __name__ == "__main__":
    est = Estado()
    print("=" * 70)
    print("mini-IdP no ar em", ISSUER)
    print("usuarios: ana.silva / Senha-Forte-Lab#1  (MFA obrigatorio)")
    print("          joao.atendente / Senha-Forte-Lab#2  (sem MFA)")
    print("segredo TOTP da ana (cadastre no app autenticador ou use totp.py):", est.otp_ana)
    print("=" * 70)
    criar_app(est).run(host="127.0.0.1", port=9000, debug=False)

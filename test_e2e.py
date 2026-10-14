"""
Teste ponta a ponta: sobe o mini-IdP de verdade (thread HTTP em localhost:9000) e exercita
o RP inseguro e o RP seguro pelo fluxo Authorization Code real.
"""
import threading
import time
import unittest
from urllib.parse import parse_qs, urlparse

import jwt
import requests
from werkzeug.serving import make_server

import app_insegura
import app_segura
import jwt_validator as jv
import mini_idp
import totp

IDP = "http://localhost:9000"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.estado = mini_idp.Estado()
        cls.idp_app = mini_idp.criar_app(cls.estado)
        cls.srv = make_server("127.0.0.1", 9000, cls.idp_app, threaded=True)
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    # --- ajudantes: fazem o papel do navegador
    def iniciar(self, rp, path="/login"):
        r = rp.get(path)
        self.assertEqual(r.status_code, 302, r.data)
        return {k: v[0] for k, v in parse_qs(urlparse(r.headers["Location"]).query).items()}

    def logar_no_idp(self, params, usuario, senha, otp=""):
        f = dict(params, username=usuario, password=senha, otp=otp)
        return requests.post(f"{IDP}/authorize", data=f, allow_redirects=False, timeout=5)

    def fluxo_completo(self, rp, usuario, senha, otp="", path="/login"):
        params = self.iniciar(rp, path)
        r = self.logar_no_idp(params, usuario, senha, otp)
        if r.status_code != 302:
            return r, None
        loc = urlparse(r.headers["Location"])
        cb = rp.get(f"{loc.path}?{loc.query}")
        return r, cb

    def obter_code(self, client_id, redirect_uri, usuario, senha, otp="", pkce=True, state="st1"):
        """Faz o papel de um cliente: gera PKCE, loga no IdP e devolve (code, verifier)."""
        import base64, hashlib, secrets
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        p = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
             "scope": "openid", "state": state, "nonce": "n-xyz"}
        if pkce:
            p.update(code_challenge=challenge, code_challenge_method="S256")
        r = self.logar_no_idp(p, usuario, senha, otp)
        self.assertEqual(r.status_code, 302, r.text)
        return parse_qs(urlparse(r.headers["Location"]).query)["code"][0], verifier

    def trocar(self, code, verifier, client_id="portal-gerente", redirect=None, secret="segredo-do-portal-gerente-lab"):
        d = {"grant_type": "authorization_code", "code": code, "client_id": client_id,
             "redirect_uri": redirect or app_segura.REDIRECT_URI, "code_verifier": verifier}
        if secret:
            d["client_secret"] = secret
        return requests.post(f"{IDP}/token", data=d, timeout=5)

    def otp_ana(self, t=None):
        return totp.totp(self.estado.otp_ana, t)


class TestIdP(Base):
    def test_discovery_e_jwks(self):
        d = requests.get(f"{IDP}/.well-known/openid-configuration", timeout=5).json()
        self.assertEqual(d["issuer"], IDP)
        self.assertEqual(d["code_challenge_methods_supported"], ["S256"])
        k = requests.get(d["jwks_uri"], timeout=5).json()["keys"][0]
        self.assertEqual((k["kty"], k["alg"], k["use"]), ("RSA", "RS256", "sig"))
        self.assertNotIn("d", k)                                  # nunca expor a chave privada

    def test_redirect_uri_nao_registrada_nao_redireciona(self):
        r = requests.get(f"{IDP}/authorize", params={
            "response_type": "code", "client_id": "portal-gerente", "scope": "openid",
            "redirect_uri": "http://evil.exemplo/callback"}, allow_redirects=False, timeout=5)
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("Location", r.headers)

    def test_redirect_uri_prefixo_nao_vale(self):
        r = requests.get(f"{IDP}/authorize", params={
            "response_type": "code", "client_id": "portal-gerente", "scope": "openid",
            "redirect_uri": "http://localhost:5001/callback/../../evil"}, allow_redirects=False, timeout=5)
        self.assertEqual(r.status_code, 400)

    def test_cliente_publico_exige_pkce(self):
        r = requests.get(f"{IDP}/authorize", params={
            "response_type": "code", "client_id": "app-mobile", "scope": "openid",
            "redirect_uri": "http://localhost:5003/callback", "state": "s"}, allow_redirects=False, timeout=5)
        self.assertEqual(r.status_code, 302)
        self.assertIn("error=invalid_request", r.headers["Location"])


class TestRPSeguro(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_segura.CLIENT_SECRET = "segredo-do-portal-gerente-lab"   # em producao vem do cofre/ambiente

    def rp(self):
        return app_segura.criar_app(secure_cookies=False).test_client()

    def test_login_completo_com_mfa(self):
        rp = self.rp()
        _, cb = self.fluxo_completo(rp, "ana.silva", "Senha-Forte-Lab#1", self.otp_ana())
        self.assertEqual(cb.status_code, 302)
        self.assertEqual(rp.get("/").get_json()["usuario"], "ana.silva")
        r = rp.get("/gerencia/limites")
        self.assertEqual(r.status_code, 200)                      # acr=2 -> step-up satisfeito

    def test_atendente_sem_mfa_loga_mas_nao_acessa_operacao_gerencial(self):
        rp = self.rp()
        _, cb = self.fluxo_completo(rp, "joao.atendente", "Senha-Forte-Lab#2")
        self.assertEqual(cb.status_code, 302)
        self.assertEqual(rp.get("/gerencia/limites").status_code, 403)

    def test_senha_correta_sem_otp_falha(self):
        r, cb = self.fluxo_completo(self.rp(), "ana.silva", "Senha-Forte-Lab#1", "")
        self.assertEqual(r.status_code, 401)

    def test_senha_errada_e_otp_errado_mesma_mensagem(self):
        rp = self.rp()
        p = self.iniciar(rp)
        a = self.logar_no_idp(p, "ana.silva", "errada", self.otp_ana())
        b = self.logar_no_idp(p, "ana.silva", "Senha-Forte-Lab#1", "000000")
        c = self.logar_no_idp(p, "usuario.inexistente", "x", "")
        self.assertEqual((a.text, b.text, c.text), ("credenciais invalidas",) * 3)

    def test_replay_de_otp_barrado_no_idp_real(self):
        cod = self.otp_ana()
        r1 = self.logar_no_idp({"response_type": "code", "client_id": "portal-gerente", "scope": "openid",
                                "redirect_uri": app_segura.REDIRECT_URI}, "ana.silva", "Senha-Forte-Lab#1", cod)
        r2 = self.logar_no_idp({"response_type": "code", "client_id": "portal-gerente", "scope": "openid",
                                "redirect_uri": app_segura.REDIRECT_URI}, "ana.silva", "Senha-Forte-Lab#1", cod)
        # r1 pode falhar se outro teste ja consumiu este passo de 30s; o que importa: nunca dois sucessos
        self.assertFalse(r1.status_code == 302 and r2.status_code == 302)
        self.assertEqual(r2.status_code, 401)

    def test_state_ausente_barrado(self):
        rp = self.rp()
        params = self.iniciar(rp)
        r = self.logar_no_idp(params, "joao.atendente", "Senha-Forte-Lab#2")
        loc = urlparse(r.headers["Location"])
        code = parse_qs(loc.query)["code"][0]
        self.assertEqual(rp.get(f"/callback?code={code}").status_code, 400)       # sem state
        self.assertEqual(rp.get(f"/callback?code={code}&state=forjado").status_code, 400)

    def test_login_csrf_codigo_do_atacante_barrado(self):
        # atacante se autentica na SUA conta e entrega a URL de callback para a vitima
        atacante, vitima = self.rp(), self.rp()
        p_atq = self.iniciar(atacante)
        r = self.logar_no_idp(p_atq, "joao.atendente", "Senha-Forte-Lab#2")
        loc = urlparse(r.headers["Location"])
        self.iniciar(vitima)                                      # vitima tem sua propria sessao/state
        resp = vitima.get(f"{loc.path}?{loc.query}")              # vitima clica no link do atacante
        self.assertEqual(resp.status_code, 400)
        self.assertIsNone(vitima.get("/").get_json()["usuario"])

    def test_codigo_nao_pode_ser_reutilizado(self):
        code, ver = self.obter_code("portal-gerente", app_segura.REDIRECT_URI, "joao.atendente", "Senha-Forte-Lab#2")
        self.assertEqual(self.trocar(code, ver).status_code, 200)
        r2 = self.trocar(code, ver)                                # mesma troca de novo
        self.assertEqual(r2.status_code, 400)
        self.assertEqual(r2.json()["error"], "invalid_grant")

    def test_code_com_redirect_uri_diferente_na_troca(self):
        code, ver = self.obter_code("portal-gerente", app_segura.REDIRECT_URI, "joao.atendente", "Senha-Forte-Lab#2")
        r = self.trocar(code, ver, redirect="http://localhost:5001/callback")
        self.assertEqual(r.json()["error"], "invalid_grant")

    def test_cliente_confidencial_com_segredo_errado(self):
        code, ver = self.obter_code("portal-gerente", app_segura.REDIRECT_URI, "joao.atendente", "Senha-Forte-Lab#2")
        self.assertEqual(self.trocar(code, ver, secret="chute").status_code, 401)

    def test_cliente_publico_pkce_ok_e_verifier_errado(self):
        ru = "http://localhost:5003/callback"
        code, ver = self.obter_code("app-mobile", ru, "joao.atendente", "Senha-Forte-Lab#2")
        r = self.trocar(code, ver, client_id="app-mobile", redirect=ru, secret=None)
        self.assertEqual(r.status_code, 200)
        code, ver = self.obter_code("app-mobile", ru, "joao.atendente", "Senha-Forte-Lab#2")
        r = self.trocar(code, "verifier-do-atacante", client_id="app-mobile", redirect=ru, secret=None)
        self.assertEqual(r.json()["error"], "invalid_grant")

    def test_pkce_verifier_errado(self):
        rp = self.rp()
        params = self.iniciar(rp)
        r = self.logar_no_idp(params, "joao.atendente", "Senha-Forte-Lab#2")
        code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
        tok = requests.post(f"{IDP}/token", timeout=5, data={
            "grant_type": "authorization_code", "code": code, "client_id": "portal-gerente",
            "client_secret": "segredo-do-portal-gerente-lab", "redirect_uri": app_segura.REDIRECT_URI,
            "code_verifier": "verifier-do-atacante-que-interceptou-o-code"})
        self.assertEqual(tok.json().get("error"), "invalid_grant")

    def test_open_redirect_neutralizado(self):
        for mal in ["https://evil.exemplo", "//evil.exemplo", "/\\evil.exemplo", "javascript:alert(1)",
                    "http://localhost:5002@evil.exemplo"]:
            self.assertEqual(app_segura._destino_seguro(mal), "/", mal)
        self.assertEqual(app_segura._destino_seguro("/gerencia/limites"), "/gerencia/limites")
        rp = self.rp()
        _, cb = self.fluxo_completo(rp, "joao.atendente", "Senha-Forte-Lab#2", path="/login?next=//evil.exemplo")
        self.assertEqual(urlparse(cb.headers["Location"]).path, "/")
        self.assertEqual(urlparse(cb.headers["Location"]).netloc, "")

    def test_idp_fora_do_ar_falha_fechada_no_callback(self):
        rp = self.rp()
        with rp.session_transaction() as s:
            s["state"], s["nonce"], s["verifier"] = "st-ok", "n-ok", "v-ok"
        original = app_segura.IDP
        app_segura.IDP = "http://127.0.0.1:9"                      # porta fechada: IdP "fora do ar"
        try:
            r = rp.get("/callback?code=qualquer&state=st-ok")
        finally:
            app_segura.IDP = original
        self.assertEqual(r.status_code, 503)                       # nao 500, e ninguem e logado
        self.assertIsNone(rp.get("/").get_json()["usuario"])

    def test_api_rejeita_token_forjado(self):
        atacante = __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["x"]).generate_private_key(65537, 2048)
        agora = int(time.time())
        forjado = jwt.encode({"iss": IDP, "aud": "api-contas", "sub": "ana.silva", "iat": agora,
                              "exp": agora + 300}, atacante, "RS256", headers={"kid": mini_idp.KID})
        r = self.rp().get("/api/me", headers={"Authorization": f"Bearer {forjado}"})
        self.assertEqual(r.status_code, 401)

    def test_api_aceita_access_token_legitimo_e_acr_no_id_token(self):
        code, ver = self.obter_code("portal-gerente", app_segura.REDIRECT_URI, "joao.atendente", "Senha-Forte-Lab#2")
        tok = self.trocar(code, ver).json()
        r = self.rp().get("/api/me", headers={"Authorization": f"Bearer {tok['access_token']}"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["sub"], "joao.atendente")
        # o ID token nao serve como access token da API (aud diferente) - confusao de tokens barrada
        r2 = self.rp().get("/api/me", headers={"Authorization": f"Bearer {tok['id_token']}"})
        self.assertEqual(r2.status_code, 401)
        idc = jwt.decode(tok["id_token"], options={"verify_signature": False})
        self.assertEqual((idc["amr"], idc["acr"]), (["pwd"], "1"))


class TestRPInseguro(Base):
    def rp(self):
        return app_insegura.criar_app().test_client()

    def test_fluxo_normal_funciona(self):
        rp = self.rp()
        _, cb = self.fluxo_completo(rp, "joao.atendente", "Senha-Forte-Lab#2")
        self.assertEqual(rp.get("/").get_json()["usuario"], "joao.atendente")

    def test_login_csrf_funciona_contra_inseguro(self):
        atacante, vitima = self.rp(), self.rp()
        p = self.iniciar(atacante)
        r = self.logar_no_idp(p, "joao.atendente", "Senha-Forte-Lab#2")
        loc = urlparse(r.headers["Location"])
        resp = vitima.get(f"{loc.path}?{loc.query}")              # sem state: aceita
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(vitima.get("/").get_json()["usuario"], "joao.atendente")   # vitima logada na conta do atacante

    def test_open_redirect_funciona_contra_inseguro(self):
        rp = self.rp()
        _, cb = self.fluxo_completo(rp, "joao.atendente", "Senha-Forte-Lab#2", path="/login?next=https://evil.exemplo/phishing")
        self.assertEqual(cb.headers["Location"], "https://evil.exemplo/phishing")

    def test_api_aceita_token_forjado_admin(self):
        forjado = jv.montar_jwt({"alg": "none"}, {"sub": "admin", "roles": ["gerente"]})
        r = self.rp().get("/api/me", headers={"Authorization": f"Bearer {forjado}"})
        self.assertEqual(r.get_json(), {"sub": "admin", "roles": ["gerente"]})


if __name__ == "__main__":
    unittest.main()

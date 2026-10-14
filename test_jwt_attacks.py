"""
Ataques classicos a validacao de JWT - cada teste mostra o ataque FUNCIONANDO contra o
validador vulneravel e BLOQUEADO pelo validador seguro.
"""
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import jwt_validator as jv

ISS = "https://idp.banco.exemplo/realms/interno"
AUD = "portal-gerente"
KID = "k1"


def gerar_chave():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = gerar_chave()
        cls.pub = cls.priv.public_key()
        cls.pem = jv.pem_publica(cls.pub)
        cls.jwks = jv.jwks_de(cls.pub, KID)
        cls.atacante = gerar_chave()                       # chave que o atacante controla

    def claims(self, **extra):
        agora = int(time.time())
        c = {"iss": ISS, "aud": AUD, "sub": "ana.silva", "iat": agora, "exp": agora + 300,
             "nonce": "n-123", "preferred_username": "ana.silva", "roles": ["atendente"]}
        c.update(extra)
        return c

    def legitimo(self, **extra):
        return jwt.encode(self.claims(**extra), self.priv, algorithm="RS256", headers={"kid": KID})


class TestAtaques(Base):
    # ---- ataque 1: remover a verificacao de assinatura
    def test_forjar_admin_sem_assinatura(self):
        forjado = jwt.encode(self.claims(sub="admin", roles=["admin"]), self.atacante,
                             algorithm="RS256", headers={"kid": KID})
        self.assertEqual(jv.validar_sem_assinatura(forjado)["sub"], "admin")     # vulneravel: aceita
        with self.assertRaises(jv.TokenInvalido):                                # seguro: recusa
            jv.validar_seguro(forjado, self.jwks, ISS, AUD, "n-123")

    # ---- ataque 2: alg=none
    def test_alg_none(self):
        forjado = jv.montar_jwt({"alg": "none", "typ": "JWT"}, self.claims(sub="admin", roles=["admin"]))
        self.assertEqual(jv.validar_ingenuo(forjado, self.pem)["sub"], "admin")
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(forjado, self.jwks, ISS, AUD, "n-123")

    def test_alg_none_variacoes_de_caixa(self):
        for alg in ["None", "NONE", "nOnE"]:
            forjado = jv.montar_jwt({"alg": alg, "typ": "JWT"}, self.claims(sub="admin"))
            self.assertEqual(jv.validar_ingenuo(forjado, self.pem)["sub"], "admin")
            with self.assertRaises(jv.TokenInvalido):
                jv.validar_seguro(forjado, self.jwks, ISS, AUD, "n-123")

    # ---- ataque 3: confusao de algoritmo RS256 -> HS256 (usa a chave PUBLICA como segredo HMAC)
    def test_key_confusion_rs256_para_hs256(self):
        import hashlib
        import hmac
        header = {"alg": "HS256", "typ": "JWT", "kid": KID}
        payload = self.claims(sub="admin", roles=["admin"])
        h = jv.b64u(__import__("json").dumps(header, separators=(",", ":")).encode())
        p = jv.b64u(__import__("json").dumps(payload, separators=(",", ":")).encode())
        assinatura = hmac.new(self.pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
        forjado = f"{h}.{p}.{jv.b64u(assinatura)}"
        self.assertEqual(jv.validar_ingenuo(forjado, self.pem)["sub"], "admin")  # explorado
        with self.assertRaises(jv.TokenInvalido):                                # lista fixa de algs
            jv.validar_seguro(forjado, self.jwks, ISS, AUD, "n-123")

    def test_pyjwt_ja_protege_contra_confusion_quando_algs_e_fixo(self):
        forjado = jwt.encode(self.claims(), "segredo-qualquer-com-mais-de-32-bytes-ok-123", algorithm="HS256", headers={"kid": KID})
        with self.assertRaises(jwt.PyJWTError):
            jwt.decode(forjado, self.pem, algorithms=["RS256"], audience=AUD, issuer=ISS)

    # ---- ataque 4: token de OUTRA aplicacao (audience confusion) / outro emissor
    def test_audience_confusion(self):
        outro_app = self.legitimo(aud="app-do-rh")          # assinado pelo IdP, mas para outro cliente
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(outro_app, self.jwks, ISS, AUD, "n-123")

    def test_issuer_errado(self):
        t = self.legitimo(iss="https://idp.falso.exemplo/realms/interno")
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    # ---- ataque 5: expirado / replay (nonce) / iat antigo
    def test_token_expirado(self):
        agora = int(time.time())
        t = self.legitimo(iat=agora - 4000, exp=agora - 3000)
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    def test_nonce_diferente_replay(self):
        t = self.legitimo(nonce="nonce-de-outra-sessao")
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    def test_emitido_ha_muito_tempo_mesmo_nao_expirado(self):
        agora = int(time.time())
        t = self.legitimo(iat=agora - 7200, exp=agora + 600)
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    # ---- ataque 6: kid desconhecido / chave do atacante com kid copiado
    def test_kid_desconhecido(self):
        t = jwt.encode(self.claims(), self.atacante, algorithm="RS256", headers={"kid": "kid-do-atacante"})
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    def test_kid_copiado_mas_assinatura_do_atacante(self):
        t = jwt.encode(self.claims(), self.atacante, algorithm="RS256", headers={"kid": KID})
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    # ---- ataque 7: claims obrigatorias ausentes
    def test_sem_exp(self):
        c = self.claims()
        c.pop("exp")
        t = jwt.encode(c, self.priv, algorithm="RS256", headers={"kid": KID})
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    def test_multiplos_aud_sem_azp(self):
        t = self.legitimo(aud=[AUD, "app-do-rh"])
        with self.assertRaises(jv.TokenInvalido):
            jv.validar_seguro(t, self.jwks, ISS, AUD, "n-123")

    # ---- caminho feliz
    def test_token_legitimo_passa(self):
        c = jv.validar_seguro(self.legitimo(), self.jwks, ISS, AUD, "n-123")
        self.assertEqual(c["sub"], "ana.silva")

    def test_token_corrompido(self):
        for lixo in ["", "abc", "a.b", "a.b.c.d", "....", "eyJhbGciOiJSUzI1NiJ9.e30.xx"]:
            with self.assertRaises(jv.TokenInvalido):
                jv.validar_seguro(lixo, self.jwks, ISS, AUD)


if __name__ == "__main__":
    unittest.main()

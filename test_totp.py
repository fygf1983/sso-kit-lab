import unittest

import totp

# Vetores de teste oficiais: RFC 4226 (Apendice D) e RFC 6238 (Apendice B)
SEG_ASCII = b"12345678901234567890"
SEG_SHA256 = b"12345678901234567890123456789012"
SEG_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"


class TestHOTP(unittest.TestCase):
    def test_rfc4226_apendice_d(self):
        esperado = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        for contador, cod in enumerate(esperado):
            self.assertEqual(totp._hotp_bytes(SEG_ASCII, contador), cod)


class TestTOTP(unittest.TestCase):
    def test_rfc6238_sha1(self):
        casos = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
                 1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
        for t, cod in casos.items():
            self.assertEqual(totp.totp_bytes(SEG_ASCII, t, digits=8), cod)

    def test_rfc6238_sha256_sha512(self):
        self.assertEqual(totp.totp_bytes(SEG_SHA256, 59, digits=8, algo="sha256"), "46119246")
        self.assertEqual(totp.totp_bytes(SEG_SHA512, 59, digits=8, algo="sha512"), "90693936")


class TestVerificador(unittest.TestCase):
    def setUp(self):
        self.seg = totp.novo_segredo()
        self.v = totp.VerificadorTOTP()

    def test_aceita_codigo_atual(self):
        t = 1_700_000_000
        self.assertTrue(self.v.verificar("ana", self.seg, totp.totp(self.seg, t), t))

    def test_bloqueia_replay(self):
        t = 1_700_000_000
        cod = totp.totp(self.seg, t)
        self.assertTrue(self.v.verificar("ana", self.seg, cod, t))
        self.assertFalse(self.v.verificar("ana", self.seg, cod, t + 5))   # mesmo codigo de novo

    def test_tolera_um_passo_de_relogio(self):
        t = 1_700_000_000
        cod_anterior = totp.totp(self.seg, t - 30)
        self.assertTrue(self.v.verificar("ana", self.seg, cod_anterior, t))

    def test_rejeita_dois_passos_de_diferenca(self):
        t = 1_700_000_000
        cod_antigo = totp.totp(self.seg, t - 90)
        self.assertFalse(self.v.verificar("ana", self.seg, cod_antigo, t))

    def test_rejeita_formato_invalido(self):
        for lixo in ["", "12345", "1234567", "abcdef", "12 456"]:
            self.assertFalse(self.v.verificar("ana", self.seg, lixo, 1_700_000_000))

    def test_uri_otpauth(self):
        u = totp.uri_otpauth("Banco Exemplo", "ana.silva", self.seg)
        self.assertTrue(u.startswith("otpauth://totp/Banco%20Exemplo%3Aana.silva?secret="))
        self.assertIn("period=30", u)


if __name__ == "__main__":
    unittest.main()

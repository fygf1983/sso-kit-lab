import time
import unittest
import xml.etree.ElementTree as ET

import saml_xsw_demo as s


class TestXSW(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = s.gerar_par()

    def resp(self, a):
        r = ET.Element("Response")
        r.append(a)
        return ET.tostring(r, encoding="utf-8")

    def test_fluxo_normal_ambos_aceitam(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        self.assertEqual(s.sp_vulneravel(self.resp(a), self.pub)["usuario"], "joao")
        self.assertEqual(s.SpSeguro(self.pub).processar(self.resp(a), "_r1")["usuario"], "joao")

    def test_xsw_engana_sp_vulneravel(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        dados = s.sp_vulneravel(s.montar_xsw(a), self.pub)
        self.assertEqual(dados["usuario"], "admin")
        self.assertEqual(dados["papel"], "gerente-geral")

    def test_xsw_barrado_pelo_sp_seguro(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(s.montar_xsw(a), "_r1")

    def test_assertion_adulterada_apos_assinar(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        a.find("Role").text = "gerente-geral"                    # troca sem reassinar
        with self.assertRaises(s.SamlInvalido):
            s.sp_vulneravel(self.resp(a), self.pub)
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_r1")

    def test_replay_bloqueado(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        sp = s.SpSeguro(self.pub)
        sp.processar(self.resp(a), "_r1")
        with self.assertRaises(s.SamlInvalido):
            sp.processar(self.resp(a), "_r1")

    def test_audience_errada(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1", audience="https://outro-sp")
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_r1")

    def test_recipient_errado(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1", recipient="https://evil/acs")
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_r1")

    def test_in_response_to_errado(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1")
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_outra-req")

    def test_expirada(self):
        a = s.emitir_assertion(self.priv, "joao", "atendente", "_r1", validade_s=-10)
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_r1")

    def test_assinada_por_outra_chave(self):
        priv2, _ = s.gerar_par()
        a = s.emitir_assertion(priv2, "admin", "gerente-geral", "_r1")
        with self.assertRaises(s.SamlInvalido):
            s.SpSeguro(self.pub).processar(self.resp(a), "_r1")


if __name__ == "__main__":
    unittest.main()

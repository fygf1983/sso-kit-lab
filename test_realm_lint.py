import json
import subprocess
import sys
import unittest

import realm_lint as rl


def ids(path):
    return {a["id"] for a in rl.analisar(json.load(open(path)))}


class TestRealmLint(unittest.TestCase):
    def test_realm_bom_sem_achados(self):
        self.assertEqual(rl.analisar(json.load(open("realms/realm_bom.json"))), [])

    def test_realm_ruim_dispara_todas_as_regras_esperadas(self):
        esperados = {f"SSO-0{n:02d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)}
        self.assertEqual(ids("realms/realm_ruim.json"), esperados)

    def test_exit_codes(self):
        run = lambda *a: subprocess.run([sys.executable, "realm_lint.py", *a], capture_output=True, text=True)
        self.assertEqual(run("realms/realm_bom.json").returncode, 0)
        self.assertEqual(run("realms/realm_ruim.json").returncode, 1)
        self.assertEqual(run("nao_existe.json").returncode, 2)

    def test_localhost_http_e_tolerado_mas_http_externo_nao(self):
        r = {"realm": "x", "sslRequired": "all", "clients": [
            {"clientId": "a", "redirectUris": ["http://localhost:3000/cb"]},
            {"clientId": "b", "redirectUris": ["http://app.exemplo/cb"]}]}
        achados = [a for a in rl.analisar(r) if a["id"] == "SSO-002"]
        self.assertEqual(len(achados), 1)
        self.assertIn("client:b", achados[0]["onde"])


if __name__ == "__main__":
    unittest.main()

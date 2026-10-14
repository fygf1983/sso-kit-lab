"""
Bateria de testes da Atividade em Grupo 1. Reaproveita os cenarios de test_jwt_attacks.py, mas
exercita a SUA funcao. Para validar o gabarito do professor:
    EXERCICIO=jwt_validator:validar_seguro python3 -m unittest test_exercicio
"""
import importlib
import os
import unittest

import jwt_validator as jv
import test_jwt_attacks as base

ALVO = os.environ.get("EXERCICIO", "exercicio_validador:validar_exercicio")
_mod, _fn = ALVO.split(":")
FUNCAO = getattr(importlib.import_module(_mod), _fn)


class TestExercicioValidador(base.TestAtaques):
    """Mesmos cenarios, mas a funcao 'segura' e a do grupo."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig = jv.validar_seguro
        jv.validar_seguro = FUNCAO

    @classmethod
    def tearDownClass(cls):
        jv.validar_seguro = cls._orig


if __name__ == "__main__":
    unittest.main()

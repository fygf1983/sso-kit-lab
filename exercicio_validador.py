"""
exercicio_validador.py - ATIVIDADE EM GRUPO 1: complete o validador de ID Token.

Regra do jogo: implemente `validar_exercicio` ate TODOS os testes de `test_exercicio.py` ficarem verdes.
Va na ordem dos TODOs: cada um torna alguns testes verdes. Nao copie de jwt_validator.validar_seguro
(esse e o gabarito do professor) - o objetivo e o grupo CHEGAR as checagens e explicar cada uma.

Rode:  python3 -m unittest test_exercicio -v
"""
import json

import jwt
from jwt.algorithms import RSAAlgorithm

from jwt_validator import TokenInvalido      # use esta excecao para REJEITAR um token


def validar_exercicio(token: str, jwks, issuer: str, audience: str, nonce: str | None = None) -> dict:
    """Devolve as claims se (e somente se) o token for aceitavel; senao levanta TokenInvalido."""
    # TODO 1 - Leia o cabecalho SEM confiar nele (jwt.get_unverified_header).
    #          Se o formato for invalido, rejeite.
    # TODO 2 - O algoritmo 'alg' do cabecalho esta numa LISTA FIXA que VOCES definem no codigo?
    #          Qual lista? Por que nao pode vir do token?
    # TODO 3 - Localize no JWKS a chave cujo 'kid' bate com o do cabecalho. Nao achou? Rejeite.
    #          (dica: jwks pode ser um dict ou uma funcao que devolve o dict)
    # TODO 4 - Valide a ASSINATURA e as claims com jwt.decode(...): informe algorithms=[...], audience, issuer
    #          e exija as claims exp, iat, iss, aud, sub (options={"require": [...]}).
    #          Converta qualquer erro do PyJWT em TokenInvalido.
    # TODO 5 - Se 'aud' for uma lista com mais de um valor, exija azp == audience.
    # TODO 6 - Rejeite tokens emitidos ha mais de 1 hora, mesmo que ainda nao tenham expirado.
    # TODO 7 - Se um nonce foi esperado, ele precisa bater (use comparacao em tempo constante).
    raise NotImplementedError("grupo: implemente os TODOs 1 a 7")

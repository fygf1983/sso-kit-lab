#!/usr/bin/env python3
"""
jwt_validator.py - Validacao de ID Token / JWT: versao VULNERAVEL x versao SEGURA.

Contem tres validadores:
  1. validar_sem_assinatura()   -> erro classico: jwt.decode(verify_signature=False)
  2. validar_ingenuo()          -> imita bibliotecas antigas: confia no 'alg' do cabecalho
                                   (aceita 'none' e permite confusao RS256->HS256)
  3. validar_seguro()           -> o que deve ir para producao (PyJWT + checagens de claims)

Tudo aqui e para estudo em ambiente de laboratorio.
"""
import base64
import hashlib
import hmac
import json
import time

import jwt  # PyJWT
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from jwt.algorithms import RSAAlgorithm


class TokenInvalido(Exception):
    pass


# ----------------------------------------------------------------------------- utilitarios
def b64u(dados: bytes) -> str:
    return base64.urlsafe_b64encode(dados).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def montar_jwt(header: dict, payload: dict, assinatura: bytes = b"") -> str:
    """Monta um JWT 'na mao' - usado para fabricar tokens forjados nos testes."""
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64u(assinatura)}"


def pem_publica(chave_publica) -> bytes:
    return chave_publica.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def jwks_de(chave_publica, kid: str) -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(chave_publica))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


# >>> VULNERAVEL-INICIO
# ----------------------------------------------------------------------------- 1) sem assinatura
def validar_sem_assinatura(token: str) -> dict:
    """VULNERAVEL: le o payload sem checar a assinatura. Qualquer um forja qualquer usuario."""
    return jwt.decode(token, options={"verify_signature": False})


# ----------------------------------------------------------------------------- 2) ingenuo
def validar_ingenuo(token: str, chave_verificacao_pem: bytes) -> dict:
    """
    VULNERAVEL: decide o algoritmo olhando o cabecalho do PROPRIO token (controlado pelo atacante).
      - alg=none  -> aceita sem assinatura
      - alg=HS256 -> usa a CHAVE PUBLICA (que e publica!) como segredo HMAC  (key confusion)
      - alg=RS256 -> verifica RSA normalmente
    Nao confere iss/aud/exp.
    """
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64u_dec(h_b64))
        payload = json.loads(b64u_dec(p_b64))
    except Exception as e:
        raise TokenInvalido(f"formato: {e}")
    alg = header.get("alg", "")
    entrada = f"{h_b64}.{p_b64}".encode()
    if alg.lower() == "none":
        return payload
    sig = b64u_dec(s_b64)
    if alg == "HS256":
        esperado = hmac.new(chave_verificacao_pem, entrada, hashlib.sha256).digest()
        if hmac.compare_digest(esperado, sig):
            return payload
        raise TokenInvalido("assinatura HS256 invalida")
    if alg == "RS256":
        pub = serialization.load_pem_public_key(chave_verificacao_pem)
        try:
            pub.verify(sig, entrada, padding.PKCS1v15(), hashes.SHA256())
            return payload
        except Exception:
            raise TokenInvalido("assinatura RS256 invalida")
    raise TokenInvalido(f"alg nao suportado: {alg}")


# <<< VULNERAVEL-FIM
# ----------------------------------------------------------------------------- 3) seguro
ALGS_PERMITIDOS = ["RS256"]      # lista FIXA no servidor - nunca derivada do token
TEMPO_MAX_TOKEN_S = 3600         # recusa tokens emitidos ha mais de 1h (defesa em profundidade)


def validar_seguro(token: str, jwks, issuer: str, audience: str,
                   nonce: str | None = None, leeway_s: int = 30) -> dict:
    """
    Checklist de validacao de ID Token (OIDC Core 1.0, secao 3.1.3.7):
      1. algoritmo permitido (lista fixa) e 'kid' conhecido no JWKS do IdP
         (jwks pode ser dict ou funcao que o devolve - assim token lixo nem gera chamada de rede)
      2. assinatura valida
      3. iss == issuer esperado        4. aud contem o client_id (e azp, se multiplos aud)
      5. exp no futuro, iat plausivel  6. nonce == o enviado no inicio do fluxo
      7. sub presente
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise TokenInvalido(f"cabecalho invalido: {e}")
    if header.get("alg") not in ALGS_PERMITIDOS:
        raise TokenInvalido(f"alg proibido: {header.get('alg')}")
    if callable(jwks):                      # JWKS "preguicoso": so busca na rede DEPOIS das checagens baratas
        jwks = jwks()
    kid = header.get("kid")
    chave = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if not chave:
        raise TokenInvalido("kid desconhecido")
    pub = RSAAlgorithm.from_jwk(json.dumps(chave))
    try:
        claims = jwt.decode(
            token, pub, algorithms=ALGS_PERMITIDOS, audience=audience, issuer=issuer,
            leeway=leeway_s, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.PyJWTError as e:
        raise TokenInvalido(str(e))
    aud = claims["aud"]
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != audience:
        raise TokenInvalido("multiplos aud exigem azp == client_id")
    if time.time() - claims["iat"] > TEMPO_MAX_TOKEN_S:
        raise TokenInvalido("token emitido ha muito tempo")
    if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise TokenInvalido("nonce nao confere (possivel replay)")
    return claims

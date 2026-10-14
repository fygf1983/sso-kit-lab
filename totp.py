#!/usr/bin/env python3
"""
totp.py - HOTP (RFC 4226) e TOTP (RFC 6238) em Python puro (somente biblioteca padrao).

Uso didatico na aula de SSO / MFA. Em producao, use a biblioteca do seu IdP
(Keycloak, Authentik...) - o objetivo aqui e entender o algoritmo.

CLI:
  python3 totp.py novo-segredo                  -> gera segredo base32 e URI otpauth://
  python3 totp.py codigo SEGREDO_BASE32         -> codigo atual
  python3 totp.py verificar SEGREDO_BASE32 123456
"""
import base64
import hashlib
import hmac
import secrets
import struct
import sys
import time
from urllib.parse import quote


def _hotp_bytes(key: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    """HOTP = Truncate(HMAC-H(K, C)) mod 10^digits  (RFC 4226, secao 5)."""
    msg = struct.pack(">Q", counter)                       # contador de 8 bytes, big-endian
    digest = hmac.new(key, msg, getattr(hashlib, algo)).digest()
    offset = digest[-1] & 0x0F                             # dynamic truncation
    binario = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binario % (10 ** digits)).zfill(digits)


def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    return _hotp_bytes(b32decode(secret_b32), counter, digits)


def b32decode(secret_b32: str) -> bytes:
    s = secret_b32.replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def novo_segredo(n_bytes: int = 20) -> str:
    """160 bits (20 bytes) de CSPRNG, como recomenda a RFC 4226."""
    return base64.b32encode(secrets.token_bytes(n_bytes)).decode().rstrip("=")


def totp_bytes(key: bytes, t: float | None = None, step: int = 30, digits: int = 6,
               algo: str = "sha1", t0: int = 0) -> str:
    t = time.time() if t is None else t
    return _hotp_bytes(key, int((t - t0) // step), digits, algo)


def totp(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    return totp_bytes(b32decode(secret_b32), t, step, digits)


class VerificadorTOTP:
    """
    Verifica codigos com janela de tolerancia e PROTECAO CONTRA REPLAY.
    Guarda, por usuario, o ultimo 'time-step' aceito: o mesmo codigo nao vale duas vezes.
    (Em producao: guardar em banco/Redis compartilhado entre as instancias do IdP.)
    """

    def __init__(self, step: int = 30, janela: int = 1, digits: int = 6):
        self.step, self.janela, self.digits = step, janela, digits
        self._ultimo_step: dict[str, int] = {}

    def verificar(self, usuario: str, secret_b32: str, codigo: str, t: float | None = None) -> bool:
        t = time.time() if t is None else t
        if not (codigo.isdigit() and len(codigo) == self.digits):
            return False
        atual = int(t // self.step)
        key = b32decode(secret_b32)
        for delta in range(-self.janela, self.janela + 1):
            passo = atual + delta
            esperado = _hotp_bytes(key, passo, self.digits)
            if hmac.compare_digest(esperado, codigo):       # tempo constante
                if passo <= self._ultimo_step.get(usuario, -1):
                    return False                             # replay (ou codigo antigo)
                self._ultimo_step[usuario] = passo
                return True
        return False


def uri_otpauth(emissor: str, conta: str, secret_b32: str) -> str:
    """URI lida pelos apps autenticadores (Google Authenticator, FreeOTP, Aegis...)."""
    rotulo = quote(f"{emissor}:{conta}")
    return (f"otpauth://totp/{rotulo}?secret={secret_b32}&issuer={quote(emissor)}"
            f"&algorithm=SHA1&digits=6&period=30")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "novo-segredo":
        s = novo_segredo()
        print("segredo :", s)
        print("uri     :", uri_otpauth("Banco Exemplo", "ana.silva", s))
    elif len(sys.argv) == 3 and sys.argv[1] == "codigo":
        print(totp(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "verificar":
        ok = VerificadorTOTP().verificar("cli", sys.argv[2], sys.argv[3])
        print("VALIDO" if ok else "INVALIDO")
        sys.exit(0 if ok else 1)
    else:
        print(__doc__)

#!/usr/bin/env python3
"""
saml_xsw_demo.py - Demonstracao DIDATICA de XML Signature Wrapping (XSW) em SAML.

ATENCAO: modelo simplificado (sem namespaces, sem C14N completo, assinatura RSA sobre a
serializacao do elemento). O objetivo e mostrar a CLASSE de falha: o SP verifica a assinatura
de UM elemento, mas le os dados de OUTRO.  Em producao use python3-saml / xmlsec / mod_auth_mellon
ou o proprio IdP+proxy (Keycloak, oauth2-proxy) - nunca escreva seu parser SAML.

Vulneravel : valida a assinatura do <Assertion ID=...> referenciado, mas le NameID do PRIMEIRO
             <Assertion> do documento.
Seguro     : (1) exige exatamente 1 Assertion; (2) extrai os dados SOMENTE do elemento cuja
             assinatura foi verificada; (3) confere Audience, Recipient, NotOnOrAfter,
             InResponseTo e usa ID de assertion uma unica vez (anti-replay).
"""
import base64
import copy
import time
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SP_ENTITY_ID = "https://portal.banco.exemplo/sp"
SP_ACS_URL = "https://portal.banco.exemplo/saml/acs"


class SamlInvalido(Exception):
    pass


def _canon(el: ET.Element) -> bytes:
    e = copy.deepcopy(el)
    e.tail = None
    for sig in e.findall("Signature"):          # a assinatura nao cobre a si mesma
        e.remove(sig)
    return ET.tostring(e, encoding="utf-8")


def assinar_assertion(assertion: ET.Element, priv) -> None:
    sig = priv.sign(_canon(assertion), padding.PKCS1v15(), hashes.SHA256())
    s = ET.SubElement(assertion, "Signature", {"Reference": assertion.get("ID")})
    s.text = base64.b64encode(sig).decode()


def emitir_assertion(priv, usuario, papel, in_response_to, validade_s=300, audience=SP_ENTITY_ID,
                     recipient=SP_ACS_URL, assertion_id="_a1b2c3") -> ET.Element:
    a = ET.Element("Assertion", {"ID": assertion_id})
    ET.SubElement(a, "Issuer").text = "https://idp.banco.exemplo"
    ET.SubElement(a, "NameID").text = usuario
    ET.SubElement(a, "Role").text = papel
    ET.SubElement(a, "Conditions", {"NotOnOrAfter": str(int(time.time()) + validade_s)})
    ET.SubElement(a, "Audience").text = audience
    ET.SubElement(a, "SubjectConfirmationData",
                  {"Recipient": recipient, "InResponseTo": in_response_to})
    assinar_assertion(a, priv)
    return a


def _sig_ok(assertion: ET.Element, pub) -> bool:
    s = assertion.find("Signature")
    if s is None or s.get("Reference") != assertion.get("ID"):
        return False
    try:
        pub.verify(base64.b64decode(s.text), _canon(assertion), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _ler(assertion: ET.Element) -> dict:
    return {"usuario": assertion.findtext("NameID"), "papel": assertion.findtext("Role"),
            "audience": assertion.findtext("Audience")}


# ------------------------------------------------------------------ SP VULNERAVEL
def sp_vulneravel(response_xml: bytes, pub) -> dict:
    root = ET.fromstring(response_xml)
    assinadas = [a for a in root.iter("Assertion") if _sig_ok(a, pub)]
    if not assinadas:
        raise SamlInvalido("nenhuma assertion com assinatura valida")
    primeira = next(root.iter("Assertion"))          # <-- BUG: le a primeira, nao a verificada
    return _ler(primeira)


# ------------------------------------------------------------------ SP SEGURO
class SpSeguro:
    def __init__(self, pub):
        self.pub = pub
        self.ids_usados: set[str] = set()

    def processar(self, response_xml: bytes, in_response_to_esperado: str) -> dict:
        root = ET.fromstring(response_xml)
        todas = list(root.iter("Assertion"))
        if len(todas) != 1:
            raise SamlInvalido(f"esperado exatamente 1 Assertion, encontrado {len(todas)}")
        a = todas[0]
        if not _sig_ok(a, self.pub):
            raise SamlInvalido("assinatura invalida")
        if a.get("ID") in self.ids_usados:
            raise SamlInvalido("assertion ja utilizada (replay)")
        if a.findtext("Audience") != SP_ENTITY_ID:
            raise SamlInvalido("audience nao e este SP")
        c = a.find("SubjectConfirmationData")
        if c is None or c.get("Recipient") != SP_ACS_URL:
            raise SamlInvalido("recipient errado")
        if c.get("InResponseTo") != in_response_to_esperado:
            raise SamlInvalido("InResponseTo nao confere (resposta nao solicitada)")
        if time.time() >= int(a.find("Conditions").get("NotOnOrAfter")):
            raise SamlInvalido("assertion expirada")
        self.ids_usados.add(a.get("ID"))
        return _ler(a)                                  # dados SOMENTE do elemento verificado


# ------------------------------------------------------------------ ATAQUE (XSW simplificado)
def montar_xsw(assertion_legitima: ET.Element, usuario_forjado="admin", papel_forjado="gerente-geral") -> bytes:
    """
    O atacante possui uma Assertion legitima e assinada (ex.: a dele, usuario comum).
    Ele insere ANTES dela uma Assertion forjada (sem assinatura valida) e embrulha a original.
    """
    resp = ET.Element("Response")
    forjada = ET.SubElement(resp, "Assertion", {"ID": "_forjada"})
    ET.SubElement(forjada, "NameID").text = usuario_forjado
    ET.SubElement(forjada, "Role").text = papel_forjado
    ET.SubElement(forjada, "Audience").text = SP_ENTITY_ID
    ext = ET.SubElement(resp, "Extensions")
    ext.append(copy.deepcopy(assertion_legitima))
    return ET.tostring(resp, encoding="utf-8")


def gerar_par():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


if __name__ == "__main__":
    priv, pub = gerar_par()
    legit = emitir_assertion(priv, "joao.atendente", "atendente", "_req-42")
    resposta_ok = ET.tostring(ET.Element("Response", {}), encoding="utf-8")
    r = ET.Element("Response"); r.append(legit)
    ok = ET.tostring(r, encoding="utf-8")
    print("[normal ] SP vulneravel ->", sp_vulneravel(ok, pub))
    xsw = montar_xsw(legit)
    print("[XSW    ] SP vulneravel ->", sp_vulneravel(xsw, pub), "  <-- virou admin!")
    try:
        SpSeguro(pub).processar(xsw, "_req-42")
    except SamlInvalido as e:
        print("[XSW    ] SP seguro     -> RECUSADO:", e)
    print("[normal ] SP seguro     ->", SpSeguro(pub).processar(ok, "_req-42"))

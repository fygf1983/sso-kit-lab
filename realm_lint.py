#!/usr/bin/env python3
"""
realm_lint.py - Linter de seguranca para exports de realm do Keycloak (JSON).
"Analise estatica da CONFIGURACAO do IdP": roda no CI antes de qualquer import em homologacao/producao.

Uso:  python3 realm_lint.py realms/realm_ruim.json [--json] [--fail-on alta|media|baixa]
Codigo de saida: 0 = sem achados >= nivel; 1 = achados; 2 = arquivo invalido.

Regras (ids estaveis para virar politica do banco):
  SSO-001 sslRequired diferente de 'all'/'external'          SSO-008 sessao ociosa SSO > 8h
  SSO-002 redirectUris com '*' ou http:// (exceto localhost) SSO-009 sem protecao contra forca bruta
  SSO-003 fluxo implicito habilitado                          SSO-010 politica de senha ausente/fraca
  SSO-004 direct grant (ROPC) habilitado                      SSO-011 OTP nao exigido (sem required action/flow)
  SSO-005 cliente publico sem PKCE S256                       SSO-012 webOrigins '*'
  SSO-006 access token > 15 min                               SSO-013 cliente confidencial com segredo literal no export
  SSO-007 refresh/rotacao: revokeRefreshToken desligado       SSO-014 assinatura de token diferente de RS256/ES256/PS256
"""
import json
import re
import sys

ORDEM = {"baixa": 1, "media": 2, "alta": 3, "critica": 4}


def achado(id_, sev, onde, msg, corrige):
    return {"id": id_, "severidade": sev, "onde": onde, "mensagem": msg, "correcao": corrige}


def _http_nao_local(uri: str) -> bool:
    return uri.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)([:/]|$)", uri)


def analisar(realm: dict) -> list[dict]:
    a = []
    nome = realm.get("realm", "?")
    if realm.get("sslRequired", "external") not in ("all", "external"):
        a.append(achado("SSO-001", "critica", nome, f"sslRequired='{realm.get('sslRequired')}'",
                        "definir sslRequired=all (ou external)"))
    if realm.get("accessTokenLifespan", 300) > 900:
        a.append(achado("SSO-006", "alta", nome, f"accessTokenLifespan={realm['accessTokenLifespan']}s",
                        "reduzir para <= 900s (ideal 300s)"))
    if realm.get("ssoSessionIdleTimeout", 1800) > 28800:
        a.append(achado("SSO-008", "media", nome, f"ssoSessionIdleTimeout={realm['ssoSessionIdleTimeout']}s",
                        "ocioso <= 8h (bancario: 15-30 min para perfis operacionais)"))
    if not realm.get("revokeRefreshToken", False):
        a.append(achado("SSO-007", "media", nome, "revokeRefreshToken=false",
                        "ligar rotacao de refresh token (revokeRefreshToken=true)"))
    if not realm.get("bruteForceProtected", False):
        a.append(achado("SSO-009", "alta", nome, "bruteForceProtected=false", "habilitar deteccao de forca bruta"))
    pol = realm.get("passwordPolicy", "")
    if "length" not in pol or int(re.search(r"length\((\d+)\)", pol).group(1) if re.search(r"length\((\d+)\)", pol) else 0) < 12:
        a.append(achado("SSO-010", "media", nome, f"passwordPolicy='{pol}'",
                        "exigir length(12) ou mais, notUsername, passwordHistory e passwordBlacklist"))
    if "CONFIGURE_TOTP" not in realm.get("defaultRequiredActions", []) and \
            "CONFIGURE_TOTP" not in [r.get("alias") for r in realm.get("requiredActions", []) if r.get("defaultAction")] and \
            not realm.get("otpRequiredByFlow", False):
        a.append(achado("SSO-011", "alta", nome, "nenhum mecanismo que force cadastro de OTP",
                        "marcar CONFIGURE_TOTP como required action padrao ou flow condicional por papel"))
    if realm.get("defaultSignatureAlgorithm", "RS256") not in ("RS256", "ES256", "PS256"):
        a.append(achado("SSO-014", "alta", nome, f"defaultSignatureAlgorithm={realm.get('defaultSignatureAlgorithm')}",
                        "usar RS256/ES256/PS256"))
    for c in realm.get("clients", []):
        cid = c.get("clientId", "?")
        onde = f"{nome}/client:{cid}"
        for uri in c.get("redirectUris", []):
            if "*" in uri:
                a.append(achado("SSO-002", "critica", onde, f"redirectUri com curinga: {uri}",
                                "registrar URIs exatas; curinga permite roubo de authorization code"))
            elif _http_nao_local(uri):
                a.append(achado("SSO-002", "alta", onde, f"redirectUri sem TLS: {uri}", "usar https://"))
        if c.get("implicitFlowEnabled"):
            a.append(achado("SSO-003", "alta", onde, "implicitFlowEnabled=true",
                            "desligar; usar Authorization Code + PKCE"))
        if c.get("directAccessGrantsEnabled"):
            a.append(achado("SSO-004", "alta", onde, "directAccessGrantsEnabled=true (ROPC)",
                            "desligar; a app nao deve tocar na senha do usuario"))
        attrs = c.get("attributes", {})
        if c.get("publicClient") and attrs.get("pkce.code.challenge.method") != "S256":
            a.append(achado("SSO-005", "alta", onde, "cliente publico sem PKCE S256",
                            "definir attribute pkce.code.challenge.method=S256"))
        for o in c.get("webOrigins", []):
            if o == "*":
                a.append(achado("SSO-012", "media", onde, "webOrigins='*'", "listar origens exatas"))
        if not c.get("publicClient") and c.get("secret") and c.get("secret") not in ("**********", ""):
            a.append(achado("SSO-013", "alta", onde, "segredo do cliente em texto claro no export",
                            "nao versionar secrets; injetar via cofre/variavel e rotacionar o que ja vazou"))
    return a


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    caminho = argv[1]
    como_json = "--json" in argv
    nivel = "media"
    if "--fail-on" in argv:
        nivel = argv[argv.index("--fail-on") + 1]
    try:
        realm = json.load(open(caminho, encoding="utf-8"))
    except Exception as e:
        print(f"erro lendo {caminho}: {e}", file=sys.stderr)
        return 2
    achados = analisar(realm)
    if como_json:
        print(json.dumps(achados, indent=2, ensure_ascii=False))
    else:
        for x in sorted(achados, key=lambda z: -ORDEM[z["severidade"]]):
            print(f"[{x['severidade'].upper():7}] {x['id']}  {x['onde']}\n           {x['mensagem']}\n           -> {x['correcao']}")
        print(f"\n{len(achados)} achado(s) em {caminho}")
    return 1 if any(ORDEM[x["severidade"]] >= ORDEM[nivel] for x in achados) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

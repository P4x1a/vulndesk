"""Autenticação via Active Directory / LDAP (Fase 4).

Fluxo: a pessoa entra com o usuário de rede e a senha. A plataforma faz o
*bind* no AD com essas credenciais (valida a senha) e lê os grupos da conta.
O mapeamento grupo→equipe (e quais grupos são administradores) vem do
config.yaml, em `ldap.group_map` e `ldap.admin_groups`.

Se o AD estiver desligado (LDAP_ENABLED≠1) ou indisponível, o /api/login cai
para as contas locais — por isso a conta da Segurança continua funcionando
mesmo com o AD fora do ar.

Config por variáveis de ambiente (.env):
  LDAP_ENABLED=1
  LDAP_SERVER=ldaps://dc01.example.local:636   (ou ldap://...:389)
  LDAP_DOMAIN=example.local                     (sufixo UPN: usuario@dominio)
  LDAP_BASE_DN=DC=example,DC=local              (base para buscar grupos)
  LDAP_START_TLS=0                                  (1 p/ STARTTLS em ldap://)
  LDAP_BIND_USER / LDAP_BIND_PASSWORD   (opcional: conta de serviço só-leitura
                                         p/ resolver grupos; sem ela, usa a
                                         própria credencial da pessoa)
"""
from __future__ import annotations
import os
import logging

log = logging.getLogger("ldap")


def ldap_enabled() -> bool:
    return os.environ.get("LDAP_ENABLED", "0") in ("1", "true", "True", "yes")


def _server():
    from ldap3 import Server, Tls
    import ssl
    uri = os.environ.get("LDAP_SERVER", "")
    use_ssl = uri.lower().startswith("ldaps://")
    tls = Tls(validate=ssl.CERT_NONE) if use_ssl or os.environ.get("LDAP_START_TLS") == "1" else None
    return Server(uri, use_ssl=use_ssl, get_info="NONE", tls=tls, connect_timeout=6)


def _user_principal(username: str) -> str:
    """Monta o login aceito pelo AD a partir do que a pessoa digitou."""
    if "@" in username or "\\" in username:
        return username
    domain = os.environ.get("LDAP_DOMAIN", "")
    return f"{username}@{domain}" if domain else username


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _cn(dn_or_name: str) -> str:
    cn = _norm(dn_or_name).split(",", 1)[0]
    return cn[3:] if cn.startswith("cn=") else cn


def _match_group(dn_or_name: str, mapping: dict):
    """Casa um DN de grupo (ou CN) contra as chaves do mapeamento e devolve o
    valor (pode ser um id de equipe ou uma lista de ids). Aceita DN completo ou
    só o CN do grupo."""
    d = _norm(dn_or_name)
    cn = _cn(dn_or_name)
    for key, val in mapping.items():
        if _norm(key) == d or _cn(key) == cn:
            return val
    return None


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def authenticate(cfg: dict, username: str, password: str) -> dict | None:
    """Valida a senha no AD e resolve equipe/role pelos grupos.

    Retorna {"team","role","nome","sub"} em caso de sucesso, ou None se as
    credenciais forem inválidas. Lança RuntimeError se o AD estiver indisponível
    (para o chamador cair no login local)."""
    if not username or not password:
        return None
    try:
        from ldap3 import Connection, SUBTREE
        from ldap3.core.exceptions import LDAPBindError, LDAPException
    except ImportError:
        raise RuntimeError("ldap3 não instalado")

    ldcfg = (cfg.get("ldap") or {})
    group_map = ldcfg.get("group_map") or {}
    admin_groups = [_norm(g) for g in (ldcfg.get("admin_groups") or [])]
    admin_users = {_norm(u) for u in (ldcfg.get("admin_users") or [])}
    base_dn = os.environ.get("LDAP_BASE_DN", ldcfg.get("base_dn", ""))
    upn = _user_principal(username)

    server = _server()
    # 1) valida a senha com o bind da própria pessoa
    try:
        user_conn = Connection(server, user=upn, password=password, auto_bind=True, receive_timeout=6)
    except LDAPBindError:
        return None   # usuário/senha inválidos
    except LDAPException as e:
        raise RuntimeError(f"AD indisponível: {e}")

    # 2) resolve nome e grupos (com conta de serviço, se houver; senão reusa a da pessoa)
    try:
        bind_user = os.environ.get("LDAP_BIND_USER")
        bind_pw = os.environ.get("LDAP_BIND_PASSWORD")
        if bind_user and bind_pw:
            conn = Connection(server, user=bind_user, password=bind_pw, auto_bind=True, receive_timeout=6)
        else:
            conn = user_conn
        flt = f"(|(userPrincipalName={upn})(sAMAccountName={username.split('@')[0].split(chr(92))[-1]}))"
        conn.search(base_dn, flt, search_scope=SUBTREE,
                    attributes=["memberOf", "displayName", "cn", "sAMAccountName"])
        if not conn.entries:
            return None
        e = conn.entries[0]
        nome = (str(e.displayName) if "displayName" in e and e.displayName else
                str(e.cn) if "cn" in e else username)
        sam = str(e.sAMAccountName) if "sAMAccountName" in e and e.sAMAccountName else username
        groups = [str(g) for g in (e.memberOf.values if "memberOf" in e else [])]
    except Exception as ex:
        raise RuntimeError(f"AD: falha ao ler grupos: {ex}")
    finally:
        try:
            user_conn.unbind()
        except Exception:
            pass

    # 3) mapeia grupo → equipe(s). Um grupo pode cobrir várias áreas (ex.: SEC-OPS
    #    = Infra+Telecom+SI). A pessoa pode editar a união das áreas dos grupos.
    editable = []
    for g in groups:
        for t in _as_list(_match_group(g, group_map)):
            if t not in editable:
                editable.append(t)

    # admin: por login (lista admin_users) OU por grupo (admin_groups)
    is_admin = _norm(sam) in admin_users or _norm(username) in admin_users \
        or any(_match_group(g, {ag: ag for ag in admin_groups}) for g in groups)

    if not editable and not is_admin:
        log.warning("LDAP: %s sem grupo mapeado para equipe", username)
        return {"team": None, "teams": [], "role": None, "nome": nome, "sub": sam}

    # equipe "primária" só para exibição/rótulo; admin sem área vira a admin_team
    primary = editable[0] if editable else cfg.get("admin_team")
    role = "admin" if is_admin else "equipe"
    return {"team": primary, "teams": editable, "role": role, "nome": nome, "sub": sam}

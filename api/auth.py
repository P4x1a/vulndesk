"""Autenticação simples por equipe (Fase 2).

Cada equipe tem um login e senha. O token é assinado (itsdangerous) e carrega a
equipe e o papel. A integração com AD/LDAP é a Fase 4; a interface aqui já fica
preparada para trocar só este módulo.
"""
from __future__ import annotations
import os
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

SECRET = os.environ.get("APP_SECRET", "troque-este-segredo-no-.env")
TOKEN_MAX_AGE = int(os.environ.get("TOKEN_MAX_AGE", 8 * 3600))  # 8h

_pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
_ser = URLSafeTimedSerializer(SECRET, salt="vuln-auth")


def hash_password(pw: str) -> str:
    return _pwd.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bool(hashed) and _pwd.verify(pw, hashed)
    except Exception:
        return False


def make_token(team_id: str, role: str, sub: str | None = None, nome: str | None = None,
               teams: list[str] | None = None) -> str:
    """Gera o token de sessão. 'sub' é o login (AD) e 'nome' o nome exibido;
    'teams' são as equipes que o usuário pode editar (admin edita todas).
    Para contas locais, 'sub' fica igual ao id da equipe e 'teams'=[equipe]."""
    data = {"team": team_id, "role": role, "sub": sub or team_id}
    if nome:
        data["nome"] = nome
    data["teams"] = teams if teams is not None else ([team_id] if team_id else [])
    return _ser.dumps(data)


def read_token(token: str) -> dict | None:
    try:
        return _ser.loads(token, max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None

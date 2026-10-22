"""API da plataforma de gestão de vulnerabilidades (Fase 2).

Expõe os dados do banco para o portal: login por equipe, listagem/edição de
ações (status, responsável, observação) com histórico, e o feed agregado que o
dashboard consome. Serve também o próprio painel (web/).
"""
from __future__ import annotations
import os
import datetime as dt
from pathlib import Path

import yaml
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select, func

from .db import Base, engine, get_session
from . import models, auth, sync, ldap_auth

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = os.environ.get("CONFIG_PATH", str(ROOT / "config" / "config.yaml"))

app = FastAPI(title="Plataforma de Gestão de Vulnerabilidades", version="2.0")


def load_config() -> dict:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def seed_teams():
    """Cria as equipes do config no banco (uma vez), com senha padrão."""
    cfg = load_config()
    default_pw = os.environ.get("DEFAULT_TEAM_PASSWORD", "mudar@123")
    admin_team = cfg.get("admin_team", "seg")
    with get_session_ctx() as db:
        for t in cfg["teams"]:
            if db.get(models.Team, t["id"]):
                continue
            db.add(models.Team(
                id=t["id"], nome=t["nome"], email=t.get("para", t.get("email", "")),
                cc=t.get("cc", ""), role="admin" if t["id"] == admin_team else "equipe",
                password_hash=auth.hash_password(t.get("senha") or default_pw),
            ))
        db.commit()


class _Ctx:
    def __enter__(self):
        self.db = next(get_session())
        return self.db
    def __exit__(self, *a):
        self.db.close()


def get_session_ctx():
    return _Ctx()


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    seed_teams()


# ---------- auth ----------
def current(authorization: str = Header(default="")) -> dict:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    data = auth.read_token(token)
    if not data:
        raise HTTPException(401, "Sessão inválida ou expirada. Faça login novamente.")
    return data


class LoginIn(BaseModel):
    team: str | None = None      # mantido para compatibilidade (login local)
    usuario: str | None = None   # usuário de rede (AD) ou id da equipe (local)
    senha: str


def _local_login(db, ident: str, senha: str):
    t = db.get(models.Team, ident)
    if not t or not auth.verify_password(senha, t.password_hash):
        return None
    token = auth.make_token(t.id, t.role, teams=[t.id])
    return {"token": token, "team": t.id, "nome": t.nome, "role": t.role, "teams": [t.id]}


@app.post("/api/login")
def login(body: LoginIn):
    ident = (body.usuario or body.team or "").strip()
    if not ident or not body.senha:
        raise HTTPException(401, "Informe usuário e senha.")

    # 1) Active Directory / LDAP (se habilitado)
    if ldap_auth.ldap_enabled():
        cfg = load_config()
        try:
            res = ldap_auth.authenticate(cfg, ident, body.senha)
        except RuntimeError:
            res = None  # AD indisponível → tenta login local abaixo
        if res is not None:
            if not res.get("team"):
                raise HTTPException(403, "Usuário autenticado, mas sem equipe atribuída no AD. Avise a Segurança da Informação.")
            with get_session_ctx() as db:
                t = db.get(models.Team, res["team"]) if res["team"] else None
                nome = t.nome if t else (res["team"] or "")
                token = auth.make_token(res["team"], res["role"], sub=res["sub"],
                                        nome=res["nome"], teams=res.get("teams") or [])
                return {"token": token, "team": res["team"], "nome": res["nome"],
                        "equipe": nome, "role": res["role"], "teams": res.get("teams") or []}

    # 2) contas locais (reserva / quando o AD está desligado)
    with get_session_ctx() as db:
        out = _local_login(db, ident, body.senha)
        if not out:
            raise HTTPException(401, "Usuário ou senha inválida.")
        return out


@app.get("/api/me")
def me(user=Depends(current)):
    with get_session_ctx() as db:
        t = db.get(models.Team, user["team"]) if user.get("team") else None
        names = {x.id: x.nome for x in db.query(models.Team).all()}
        teams = user.get("teams") or ([user["team"]] if user.get("team") else [])
        return {"team": user.get("team"),
                "nome": user.get("nome") or (t.nome if t else user.get("team")),
                "equipe": t.nome if t else (user.get("team") or ""),
                "equipes": [names.get(x, x) for x in teams],
                "teams": teams, "role": user["role"]}


@app.get("/api/public/config")
def public_config():
    """Ajuda a tela de login a se adaptar (AD ligado = pede usuário de rede)."""
    return {"ldap": ldap_auth.ldap_enabled()}


@app.get("/api/public/teams")
def public_teams():
    """Só nomes das equipes, para o seletor da tela de login (modo local)."""
    with get_session_ctx() as db:
        return [{"id": t.id, "nome": t.nome} for t in db.query(models.Team).order_by(models.Team.nome).all()]


@app.get("/api/teams")
def teams(user=Depends(current)):
    with get_session_ctx() as db:
        return [{"id": t.id, "nome": t.nome} for t in db.query(models.Team).all()]


# ---------- dados ----------
def _sla_status(a: models.Action, hoje: dt.date) -> str:
    if a.status == "Corrigido":
        return "Corrigido"
    if a.status in ("Falso positivo", "Risco aceito"):
        return a.status
    if not a.prazo:
        return "No prazo"
    rest = (a.prazo - hoje).days
    if rest < 0:
        return "Vencido"
    if rest <= max(1, round(a.sla_dias * 0.25)):
        return "Em risco"
    return "No prazo"


def _action_dict(a: models.Action, team_names: dict, hoje: dt.date) -> dict:
    return {
        "id": a.codigo or f"A-{a.id}", "pk": a.id, "key": a.action_key,
        "titulo": a.titulo, "acao": a.acao, "threat": a.threat, "sev": a.sev,
        "prioridade": a.prioridade, "familia": a.familia, "hosts": a.hosts_count,
        "hosts_ips": a.hosts or [], "cves": len(a.cves or []), "nvts": len(a.nvts or []),
        "team": a.team, "teamNome": team_names.get(a.team, a.team),
        "status": a.status, "responsavel": a.responsavel or "", "observacao": a.observacao or "",
        "sla_dias": a.sla_dias, "prazo": a.prazo.isoformat() if a.prazo else None,
        "sla_status": _sla_status(a, hoje),
        "deteccao": a.deteccao.isoformat() if a.deteccao else None,
        "resolvido_em": a.resolvido_em.isoformat() if a.resolvido_em else None,
        "mttr": (a.resolvido_em - a.deteccao).days if (a.resolvido_em and a.deteccao) else None,
        "reincidente": bool(a.reincidente), "ativo": bool(a.ativo),
        "scanNome": a.task,
    }


@app.get("/api/scans")
def scans(user=Depends(current)):
    """Lista os scans (tarefas) disponíveis, com o último snapshot de cada um."""
    with get_session_ctx() as db:
        out, seen = [], set()
        for s in db.query(models.Snapshot).order_by(models.Snapshot.id.desc()).all():
            if s.task in seen:
                continue
            seen.add(s.task)
            out.append({"task": s.task, "scan": s.scan_date, "hosts": s.hosts_scan,
                        "total": s.total, "abertas": s.abertas, "criticas": s.criticas, "altas": s.altas})
        return out


_SEVN = ["Critical", "High", "Medium", "Low"]


@app.get("/api/dashboard")
def dashboard(task: str | None = None, user=Depends(current)):
    hoje = dt.date.today()
    with get_session_ctx() as db:
        team_names = {t.id: t.nome for t in db.query(models.Team).all()}
        total_scans = db.query(models.Snapshot.task).distinct().count()
        todos = task == "__all__"
        if not todos:
            last = db.query(models.Snapshot)
            if task:
                last = last.filter_by(task=task)
            last = last.order_by(models.Snapshot.id.desc()).first()
            if not last:
                return {"meta": {"tarefa": "—", "hostsScan": 0, "total": 0, "hoje": hoje.isoformat(),
                                 "nota": "Nenhum scan importado ainda."}, "acoes": [], "evolucao": [], "scans": total_scans}
            task = last.task
            rows = db.query(models.Action).filter_by(task=task).all()
            evsnaps = db.query(models.Snapshot).filter_by(task=task).order_by(models.Snapshot.id.asc()).all()
            meta = {"tarefa": task, "alvo": last.alvo, "hostsScan": last.hosts_scan, "total": last.total,
                    "scan": last.scan_date, "hoje": hoje.isoformat(), "escopo": "scan",
                    "nota": "Dados importados automaticamente do OpenVAS via GMP."}
        else:
            rows = db.query(models.Action).all()
            # último snapshot por tarefa → somatórios de hosts/total
            latest = {}
            for s in db.query(models.Snapshot).order_by(models.Snapshot.id.asc()).all():
                latest[s.task] = s
            hostsScan = sum(s.hosts_scan for s in latest.values())
            total = sum(s.total for s in latest.values())
            scan_mais_recente = max((s.scan_date for s in latest.values()), default=hoje.isoformat())
            # evolução consolidada: soma por data de scan
            agg = {}
            for s in db.query(models.Snapshot).order_by(models.Snapshot.id.asc()).all():
                a = agg.setdefault(s.scan_date, {"semana": s.scan_date, "abertas": 0, "corrigidas": 0, "criticas": 0, "altas": 0})
                a["abertas"] += s.abertas; a["corrigidas"] += s.corrigidas; a["criticas"] += s.criticas; a["altas"] += s.altas
            evsnaps = None
            evo = sorted(agg.values(), key=lambda x: x["semana"])[-12:]
            meta = {"tarefa": f"Todos os scans ({total_scans})", "alvo": "", "hostsScan": hostsScan, "total": total,
                    "scan": scan_mais_recente, "hoje": hoje.isoformat(), "escopo": "todos",
                    "nota": "Visão consolidada de todos os scans importados."}
        rows.sort(key=lambda r: (models.STATUSES.index(r.status) if r.status in models.STATUSES else 9,
                                 _SEVN.index(r.threat) if r.threat in _SEVN else 9, r.codigo))
        acoes = [_action_dict(a, team_names, hoje) for a in rows]
        if not todos:
            evo = [{"semana": s.scan_date, "abertas": s.abertas, "corrigidas": s.corrigidas,
                    "criticas": s.criticas, "altas": s.altas} for s in evsnaps][-12:]
        return {"meta": meta, "acoes": acoes, "evolucao": evo, "scans": total_scans}


class PatchIn(BaseModel):
    status: str | None = None
    responsavel: str | None = None
    observacao: str | None = None
    team: str | None = None


@app.patch("/api/actions/{pk}")
def patch_action(pk: int, body: PatchIn, user=Depends(current)):
    with get_session_ctx() as db:
        a = db.get(models.Action, pk)
        if not a:
            raise HTTPException(404, "Ação não encontrada.")
        is_admin = user["role"] == "admin"
        my_teams = user.get("teams") or ([user["team"]] if user.get("team") else [])
        if not is_admin and a.team not in my_teams:
            raise HTTPException(403, "Esta ação é de outra equipe.")
        quem = user.get("sub") or user.get("team") or "?"
        changed = []
        if body.status is not None and body.status != a.status:
            if body.status not in models.STATUSES:
                raise HTTPException(400, "Status inválido.")
            a.history.append(models.History(quem=quem, campo="status", de=a.status, para=body.status))
            a.status = body.status
            if body.status == "Corrigido" and not a.resolvido_em:
                a.resolvido_em = dt.date.today()
            changed.append("status")
        if body.responsavel is not None and body.responsavel != a.responsavel:
            a.history.append(models.History(quem=quem, campo="responsavel", de=a.responsavel, para=body.responsavel))
            a.responsavel = body.responsavel
            changed.append("responsavel")
        if body.observacao is not None and body.observacao != a.observacao:
            a.history.append(models.History(quem=quem, campo="observacao", de=a.observacao or "", para=body.observacao))
            a.observacao = body.observacao
            changed.append("observacao")
        if body.team is not None and body.team != a.team:
            if not is_admin:
                raise HTTPException(403, "Só a Segurança pode reatribuir a equipe.")
            a.history.append(models.History(quem=quem, campo="team", de=a.team, para=body.team))
            a.team = body.team
            changed.append("team")
        db.commit()
        hoje = dt.date.today()
        team_names = {t.id: t.nome for t in db.query(models.Team).all()}
        return {"ok": True, "changed": changed, "action": _action_dict(a, team_names, hoje)}


@app.get("/api/actions/{pk}")
def action_detail(pk: int, user=Depends(current)):
    """Detalhe completo de uma ação (descrição, o que fazer, hosts, CVEs…),
    carregado sob demanda quando a linha é expandida. Qualquer usuário logado
    pode ver; editar continua restrito à equipe."""
    with get_session_ctx() as db:
        a = db.get(models.Action, pk)
        if not a:
            raise HTTPException(404, "Ação não encontrada.")
        return {
            "id": a.codigo or f"A-{a.id}", "pk": a.id, "titulo": a.titulo,
            "threat": a.threat, "sev": a.sev, "prioridade": a.prioridade,
            "familia": a.familia or "", "produto": a.produto_nome or "",
            "resumo": a.resumo or "", "acao": a.acao or "", "solucao": a.solucao or "",
            "hosts": a.hosts or [], "hosts_count": a.hosts_count,
            "portas": a.portas or {}, "cves": a.cves or [], "nvts": a.nvts or [],
            "scanNome": a.task,
        }


@app.get("/api/actions/{pk}/history")
def action_history(pk: int, user=Depends(current)):
    with get_session_ctx() as db:
        a = db.get(models.Action, pk)
        if not a:
            raise HTTPException(404, "Ação não encontrada.")
        hs = db.query(models.History).filter_by(action_id=pk).order_by(models.History.id.desc()).all()
        return [{"quando": h.quando.isoformat(timespec="seconds"), "quem": h.quem,
                 "campo": h.campo, "de": h.de, "para": h.para} for h in hs]


@app.get("/api/health")
def health():
    return {"ok": True}


# ---------- UI estática ----------
_web = ROOT / "web"
if _web.is_dir():
    app.mount("/", StaticFiles(directory=str(_web), html=True), name="web")

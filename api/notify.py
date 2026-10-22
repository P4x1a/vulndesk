"""Notificações no Microsoft Teams (Fase 4).

Envia *cards* para canais do Teams por webhook. Quatro gatilhos:
  - nova ação crítica/alta atribuída a uma equipe        (kind 'novo')
  - prazo (SLA) prestes a vencer                          (kind 'prazo')
  - ação vencida                                          (kind 'vencido')
  - resumo diário por equipe                              (digest, por tempo)

Dedupe: os três primeiros usam a tabela NotifyLog (cada alerta sai uma vez por
ação). O resumo é por tempo (uma vez ao dia), então não precisa de dedupe.

Webhooks no config.yaml → notifications.webhooks:
  default: "https://...."          # canal geral (Segurança)
  por_equipe: { infra: "https://...", redes: "https://...", ... }
O webhook de uma equipe também pode vir da env TEAMS_WEBHOOK_<EQUIPE> (ex.:
TEAMS_WEBHOOK_INFRA) e o geral de TEAMS_WEBHOOK_DEFAULT.

Uso (serviço): python -m api.notify loop   (checa SLA e manda o resumo no horário)
Avulso:         python -m api.notify sla | digest | test
"""
from __future__ import annotations
import os
import json
import time
import datetime as dt
import logging
import urllib.request
import urllib.error

log = logging.getLogger("notify")

SEV_PT = {"Critical": "Crítica", "High": "Alta", "Medium": "Média", "Low": "Baixa"}
SEV_COLOR = {"Critical": "D03B3B", "High": "EC835A", "Medium": "EDA100", "Low": "6C8FB8"}
FECHADO = {"Corrigido", "Risco aceito", "Falso positivo"}


# ---------- configuração ----------
def _ncfg(cfg: dict) -> dict:
    return cfg.get("notifications") or {}


def enabled(cfg: dict) -> bool:
    return bool(_ncfg(cfg).get("enabled")) and os.environ.get("NOTIFY_ENABLED", "1") not in ("0", "false")


def webhook_for(cfg: dict, team_id: str | None) -> str | None:
    n = _ncfg(cfg)
    wh = n.get("webhooks") or {}
    if team_id:
        env = os.environ.get(f"TEAMS_WEBHOOK_{team_id.upper()}")
        if env:
            return env
        per = (wh.get("por_equipe") or {}).get(team_id)
        if per:
            return per
    return os.environ.get("TEAMS_WEBHOOK_DEFAULT") or wh.get("default")


def portal_url(cfg: dict) -> str:
    return os.environ.get("PORTAL_URL") or _ncfg(cfg).get("portal_url", "")


# ---------- envio ----------
def post_card(url: str, card: dict) -> bool:
    """Posta um Adaptive Card no webhook do Teams (Workflows). True se aceito."""
    if not url:
        return False
    data = json.dumps(card).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
            return 200 <= r.status < 300   # Workflows responde 202 Accepted
    except urllib.error.HTTPError as e:
        log.warning("Teams HTTP %s: %s", e.code, e.reason)
    except Exception as e:
        log.warning("Teams falhou: %s", e)
    return False


# Cor de tema (hex) → estilo de container do Adaptive Card (faixa do cabeçalho).
_CONTAINER_STYLE = {
    "D03B3B": "attention", "EC835A": "warning", "EC8A3C": "warning",
    "EDA100": "warning", "0C8A0C": "good", "2BACE3": "accent", "6C8FB8": "accent",
}
# Severidade → cor do texto do "selo" na lista de itens.
_SEV_TXT = {"Critical": "Attention", "High": "Warning", "Medium": "Accent", "Low": "Default"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def _item_row(it: dict) -> dict:
    """Uma linha da lista de itens em aberto (bolinha colorida + título + meta)."""
    meta_bits = [SEV_PT.get(it["sev"], it["sev"])]
    if it.get("tag"):
        meta_bits.append(it["tag"])
    elif it.get("prazo"):
        meta_bits.append("vence " + it["prazo"])
    return {"type": "ColumnSet", "spacing": "Small", "columns": [
        {"type": "Column", "width": "auto", "verticalContentAlignment": "Center",
         "items": [{"type": "TextBlock", "text": "●", "color": _SEV_TXT.get(it["sev"], "Default"),
                    "weight": "Bolder", "spacing": "None"}]},
        {"type": "Column", "width": "stretch", "items": [
            {"type": "TextBlock", "text": it["titulo"], "wrap": True, "weight": "Bolder",
             "size": "Small", "spacing": "None"},
            {"type": "TextBlock", "text": " · ".join(meta_bits), "isSubtle": True,
             "size": "Small", "spacing": "None", "wrap": True}]},
    ]}


def _card(title: str, text: str, color: str, facts: list[tuple[str, str]] | None = None,
          items: list[dict] | None = None, more: int = 0,
          link_label: str | None = None, link_url: str | None = None) -> dict:
    """Monta a mensagem (Adaptive Card em type=message/attachments) que o fluxo
    de Workflows renderiza no canal. Cabeçalho em faixa colorida por gravidade,
    fatos em destaque e, opcionalmente, a lista de itens em aberto."""
    body = [
        {"type": "Container", "style": _CONTAINER_STYLE.get(color, "accent"), "bleed": True,
         "items": [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Large", "wrap": True}]},
    ]
    if text:
        body.append({"type": "TextBlock", "text": text, "wrap": True, "spacing": "Small", "isSubtle": True})
    if facts:
        body.append({"type": "FactSet", "facts": [{"title": n, "value": v} for n, v in facts]})
    if items:
        body.append({"type": "TextBlock", "text": "Itens em aberto", "weight": "Bolder",
                     "spacing": "Medium", "separator": True})
        body.extend(_item_row(it) for it in items)
        if more > 0:
            body.append({"type": "TextBlock", "text": f"+{more} no portal", "isSubtle": True,
                         "size": "Small", "spacing": "Small"})
    content = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    }
    if link_url:
        content["actions"] = [{"type": "Action.OpenUrl", "title": link_label or "Abrir no portal", "url": link_url}]
    return {"type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}]}


def _fmt(d) -> str:
    if not d:
        return "—"
    if isinstance(d, str):
        d = dt.date.fromisoformat(d[:10])
    return d.strftime("%d/%m/%Y")


# ---------- gatilhos ----------
def _already(session, action_id: int, kind: str) -> bool:
    from .models import NotifyLog
    return session.query(NotifyLog).filter_by(action_id=action_id, kind=kind).first() is not None


def _mark(session, action_id: int, kind: str):
    from .models import NotifyLog
    session.add(NotifyLog(action_id=action_id, kind=kind))


def notify_new(session, cfg: dict, rows, team_names: dict) -> int:
    """Alerta de novas ações crítica/alta recém-atribuídas (lista de Action)."""
    if not enabled(cfg):
        return 0
    sent = 0
    for a in rows:
        if a.threat not in ("Critical", "High") or _already(session, a.id, "novo"):
            continue
        url = webhook_for(cfg, a.team)
        card = _card(
            f"🛡️ Nova vulnerabilidade {SEV_PT[a.threat]} — {team_names.get(a.team, a.team)}",
            f"**{a.titulo}**\n\n{a.acao or ''}", SEV_COLOR[a.threat],
            facts=[("Criticidade", f"{a.prioridade} · {SEV_PT[a.threat]}"),
                   ("Hosts afetados", str(a.hosts_count)),
                   ("Prazo (SLA)", _fmt(a.prazo))],
            link_label="Tratar no portal", link_url=portal_url(cfg))
        if post_card(url, card):
            _mark(session, a.id, "novo")
            sent += 1
    session.commit()
    return sent


def check_sla(session, cfg: dict) -> dict:
    """Varre ações abertas e dispara 'prazo a vencer' e 'vencido' (uma vez cada)."""
    from .models import Action
    if not enabled(cfg):
        return {"prazo": 0, "vencido": 0}
    warn_days = int(_ncfg(cfg).get("sla_warning_days", 3))
    hoje = dt.date.today()
    team_names = _team_names(session)
    rows = session.query(Action).filter(Action.ativo.is_(True)).all()
    sent = {"prazo": 0, "vencido": 0}
    for a in rows:
        if a.status in FECHADO or not a.prazo:
            continue
        rest = (a.prazo - hoje).days
        kind = "vencido" if rest < 0 else ("prazo" if rest <= warn_days else None)
        if not kind or _already(session, a.id, kind):
            continue
        url = webhook_for(cfg, a.team)
        if kind == "vencido":
            title = f"⛔ Prazo VENCIDO — {team_names.get(a.team, a.team)}"
            text = f"**{a.titulo}**\n\nVencida há {abs(rest)} dia(s). Precisa de tratativa."
            color = "D03B3B"
        else:
            title = f"⏰ Prazo em {rest} dia(s) — {team_names.get(a.team, a.team)}"
            text = f"**{a.titulo}**\n\nSLA vence em {_fmt(a.prazo)}."
            color = "EC8A3C"
        card = _card(title, text, color,
                     facts=[("Criticidade", f"{a.prioridade} · {SEV_PT.get(a.threat, a.threat)}"),
                            ("Hosts", str(a.hosts_count)), ("Prazo", _fmt(a.prazo))],
                     link_label="Abrir portal", link_url=portal_url(cfg))
        if post_card(url, card):
            _mark(session, a.id, kind)
            sent[kind] += 1
    session.commit()
    return sent


def daily_digest(session, cfg: dict) -> int:
    """Resumo por equipe: abertas, em risco e vencidas."""
    from .models import Action, Team
    if not enabled(cfg):
        return 0
    hoje = dt.date.today()
    warn_days = int(_ncfg(cfg).get("sla_warning_days", 3))
    teams = session.query(Team).all()
    sent = 0
    for t in teams:
        rows = session.query(Action).filter(Action.team == t.id, Action.ativo.is_(True)).all()
        abertas = [a for a in rows if a.status not in FECHADO]
        if not abertas and t.role != "admin":
            continue
        venc = sum(1 for a in abertas if a.prazo and (a.prazo - hoje).days < 0)
        risco = sum(1 for a in abertas if a.prazo and 0 <= (a.prazo - hoje).days <= warn_days)
        crit = sum(1 for a in abertas if a.threat == "Critical")
        alt = sum(1 for a in abertas if a.threat == "High")
        color = "D03B3B" if (venc or crit) else ("EC8A3C" if (risco or alt) else "0C8A0C")
        # itens em aberto, mais graves primeiro (crítico→baixo, depois prazo mais perto)
        ordenadas = sorted(abertas, key=lambda a: (
            SEV_ORDER.index(a.threat) if a.threat in SEV_ORDER else 9,
            a.prazo or dt.date.max))
        top = ordenadas[:8]
        items = []
        for a in top:
            rest = (a.prazo - hoje).days if a.prazo else None
            tag = ("vencida" if (rest is not None and rest < 0) else
                   "em risco" if (rest is not None and rest <= warn_days) else "")
            items.append({"sev": a.threat, "titulo": a.titulo,
                          "prazo": _fmt(a.prazo) if a.prazo else "", "tag": tag})
        resumo = ("Tudo sob controle hoje. 🎉" if not abertas else
                  f"Situação das vulnerabilidades da equipe em {_fmt(hoje)}.")
        card = _card(
            f"📋 Resumo diário — {t.nome}", resumo, color,
            facts=[("Ações em aberto", str(len(abertas))),
                   ("Críticas / Altas", f"{crit} / {alt}"),
                   ("Em risco (≤{}d)".format(warn_days), str(risco)),
                   ("Vencidas", str(venc))],
            items=items, more=max(0, len(abertas) - len(top)),
            link_label="Ver e tratar no portal", link_url=portal_url(cfg))
        if post_card(webhook_for(cfg, t.id), card):
            sent += 1
    return sent


# ---------- utilidades / CLI ----------
def _team_names(session) -> dict:
    from .models import Team
    return {t.id: t.nome for t in session.query(Team).all()}


def _load_cfg():
    import yaml
    from pathlib import Path
    path = os.environ.get("CONFIG_PATH", str(Path(__file__).resolve().parent.parent / "config" / "config.yaml"))
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _digest_due(cfg, last: dt.date | None) -> bool:
    """True se já passou do horário do resumo e ainda não saiu hoje."""
    hhmm = str(_ncfg(cfg).get("digest_time", "08:00"))
    now = dt.datetime.now()
    try:
        h, m = (int(x) for x in hhmm.split(":"))
    except Exception:
        h, m = 8, 0
    return now.time() >= dt.time(h, m) and last != now.date()


def main(argv=None):
    import sys
    from .db import SessionLocal, Base, engine
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    Base.metadata.create_all(engine)
    cfg = _load_cfg()
    cmd = (argv or sys.argv[1:] or ["loop"])[0]

    if cmd == "test":
        url = webhook_for(cfg, None)
        ok = post_card(url, _card("✅ Teste de integração", "Notificações do portal de vulnerabilidades funcionando.", "2BACE3",
                                  link_label="Abrir portal", link_url=portal_url(cfg)))
        print("Webhook OK" if ok else "Falha no webhook (confira a URL em notifications.webhooks.default / TEAMS_WEBHOOK_DEFAULT).")
        return
    if cmd in ("sla", "digest"):
        s = SessionLocal()
        try:
            if cmd == "sla":
                print("SLA:", check_sla(s, cfg))
            else:
                print("Resumos enviados:", daily_digest(s, cfg))
        finally:
            s.close()
        return

    # loop (serviço): checa SLA no intervalo e manda o resumo no horário
    interval = int(_ncfg(cfg).get("check_interval_seconds", 1800))
    log.info("Notifier no ar: SLA a cada %ss, resumo às %s.", interval, _ncfg(cfg).get("digest_time", "08:00"))
    last_digest = None
    while True:
        try:
            cfg = _load_cfg()
            s = SessionLocal()
            try:
                res = check_sla(s, cfg)
                if any(res.values()):
                    log.info("SLA: %s", res)
                if _digest_due(cfg, last_digest):
                    n = daily_digest(s, cfg)
                    last_digest = dt.date.today()
                    log.info("Resumo diário: %s equipe(s).", n)
            finally:
                s.close()
        except Exception as e:
            log.warning("ciclo falhou: %s", e)
        time.sleep(interval)


if __name__ == "__main__":
    main()

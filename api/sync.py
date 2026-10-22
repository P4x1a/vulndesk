"""Sincroniza um relatório consolidado para o banco (importador → plataforma).

Regra de ouro: a importação atualiza os campos vindos do scan, mas **nunca
sobrescreve** a tratativa das equipes (status, responsável, observação, equipe
escolhida). Além disso detecta:
  - ações que sumiram do scan  → marcadas como Corrigido (resolvido);
  - ações resolvidas que voltaram → reincidência (reabertas);
e registra tudo no histórico.
"""
from __future__ import annotations
import datetime as dt

from importer import consolidation as C
from .models import Action, History, Snapshot, Team, STATUS_FECHADO


def _scan_date(parsed) -> str:
    s = (parsed["meta"].get("scan_end") or parsed["meta"].get("scan_start") or "")[:10]
    return s or dt.date.today().isoformat()


def _hist(row: Action, quem: str, campo: str, de, para):
    row.history.append(History(quem=quem, campo=campo, de=str(de or ""), para=str(para or "")))


def sync_report(session, task: str, report_id: str, parsed: dict, cfg: dict, is_new: bool) -> dict:
    acts = C.consolidate(parsed)
    C.assign_teams(acts, parsed, cfg)
    scan_date = _scan_date(parsed)
    scan_d = dt.date.fromisoformat(scan_date)
    sla_cfg = cfg["sla"]

    existing = {r.action_key: r for r in session.query(Action).filter_by(task=task).all()}
    current_keys = {a.key for a in acts}
    created = reopened = resolved = 0
    alert_rows = []   # ações novas/reabertas para notificar (crítica/alta)

    for a in acts:
        row = existing.get(a.key)
        dias = sla_cfg.get(a.threat, 90)
        scan_fields = dict(
            codigo=a.id, titulo=a.titulo, acao=a.acao, threat=a.threat, sev=a.sev,
            prioridade=a.prioridade, familia=a.familia, produto_nome=a.produto_nome,
            produto_key=a.produto_key, hosts_count=len(a.hosts), hosts=a.hosts,
            portas={ip: sorted(ps) for ip, ps in a.portas.items()}, cves=a.cves, nvts=a.nvts,
            resumo=a.resumo, solucao=a.solucao, team_auto=a.team_auto, sla_dias=dias,
            last_report_id=report_id, last_seen=scan_d,
        )
        if row is None:
            row = Action(task=task, action_key=a.key, deteccao=scan_d, status="Pendente",
                         team=a.team_auto, reincidente=False, vezes_visto=1, ativo=True,
                         prazo=scan_d + dt.timedelta(days=dias), **scan_fields)
            session.add(row)
            _hist(row, "sistema", "status", "", "Pendente (detectado)")
            created += 1
            existing[a.key] = row
            alert_rows.append(row)
            continue

        prev_ativo = row.ativo
        for k, v in scan_fields.items():
            setattr(row, k, v)
        if is_new:
            if not prev_ativo:
                # reapareceu depois de ter sido resolvido → reincidência
                row.reincidente = True
                row.ativo = True
                row.resolvido_em = None
                row.vezes_visto = (row.vezes_visto or 1) + 1
                old = row.status
                row.status = "Pendente"
                _hist(row, "sistema", "status", old, "Pendente (reaberto — reincidência)")
                reopened += 1
                alert_rows.append(row)
            else:
                row.ativo = True
        row.prazo = (row.deteccao or scan_d) + dt.timedelta(days=row.sla_dias)

    # ações que sumiram do scan → corrigidas (só em relatório novo)
    if is_new:
        for key, row in existing.items():
            if key not in current_keys and row.ativo:
                row.ativo = False
                row.resolvido_em = scan_d
                if row.status not in STATUS_FECHADO:
                    old = row.status
                    row.status = "Corrigido"
                    _hist(row, "sistema", "status", old, "Corrigido (não detectado no scan)")
                resolved += 1

    session.flush()

    if is_new:
        rows = session.query(Action).filter_by(task=task).all()
        abertas = sum(1 for r in rows if r.ativo and r.status not in STATUS_FECHADO)
        corrigidas = sum(1 for r in rows if r.status == "Corrigido")
        opensev = {s: sum(1 for r in rows if r.ativo and r.status not in STATUS_FECHADO and r.threat == s) for s in C.SEV}
        session.add(Snapshot(task=task, report_id=report_id, scan_date=scan_date,
                             hosts_scan=parsed["meta"].get("hosts_scan", 0),
                             total=len(parsed["findings"]), alvo=parsed["meta"].get("alvo", ""),
                             abertas=abertas, corrigidas=corrigidas,
                             criticas=opensev["Critical"], altas=opensev["High"],
                             medias=opensev["Medium"], baixas=opensev["Low"]))

    session.commit()

    # notificações (nova crítica/alta) — nunca derruba a importação
    if is_new and alert_rows:
        try:
            from . import notify
            if notify.enabled(cfg):
                team_names = {t.id: t.nome for t in session.query(Team).all()}
                notify.notify_new(session, cfg, alert_rows, team_names)
        except Exception as e:  # pragma: no cover
            import logging
            logging.getLogger("sync").warning("notificação falhou: %s", e)

    return {"created": created, "reopened": reopened, "resolved": resolved, "total": len(acts), "is_new": is_new}


def last_report_for(session, task: str) -> str | None:
    s = session.query(Snapshot).filter_by(task=task).order_by(Snapshot.id.desc()).first()
    return s.report_id if s else None

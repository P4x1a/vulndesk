"""Orquestrador — automação do scan à consolidação.

Conecta no gvmd (GMP) → opcionalmente dispara o scan → baixa o relatório mais
recente → consolida em ações → persiste.

Persistência:
  - com DATABASE_URL definido (Fase 2): grava no banco (PostgreSQL) via api.sync,
    preservando as tratativas das equipes e detectando corrigidas/reincidência;
  - sem DATABASE_URL (Fase 1): grava o feed.json.

Modos: (sem args) importa; --scan dispara; --loop serviço; --from-file offline.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import time
from pathlib import Path

import yaml

from . import consolidation as C

ROOT = Path(__file__).resolve().parent.parent


def log(msg: str):
    print(f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    g = cfg.setdefault("gmp", {})
    g["username"] = os.environ.get("GMP_USERNAME", g.get("username", ""))
    g["password"] = os.environ.get("GMP_PASSWORD", g.get("password", ""))
    return cfg


def db_mode() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


# ---------- Fase 2: persistência no banco ----------
def persist_db(task, report_id, parsed, cfg):
    from api.db import SessionLocal, Base, engine
    from api import sync
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        ident = report_id or _scan_id(parsed)
        is_new = sync.last_report_for(session, task) != ident
        res = sync.sync_report(session, task, ident, parsed, cfg, is_new)
        tag = "novo" if res["is_new"] else "sem mudança (mesmo relatório)"
        log(f"Banco atualizado [{task}]: {res['total']} ações · {tag} · "
            f"novas {res['created']}, reabertas {res['reopened']}, corrigidas {res['resolved']}")
    finally:
        session.close()


def _scan_id(parsed) -> str:
    return (parsed["meta"].get("scan_end") or parsed["meta"].get("scan_start") or dt.date.today().isoformat())[:19]


# ---------- Fase 1: feed.json ----------
def persist_feed(task, report_id, parsed, cfg, store):
    acts = C.consolidate(parsed)
    C.assign_teams(acts, parsed, cfg)
    scan_date = (parsed["meta"].get("scan_end") or parsed["meta"].get("scan_start") or "")[:10] or dt.date.today().isoformat()
    base_date = dt.date.fromisoformat(scan_date) if cfg.get("base_data") == "scan" else dt.date.today()
    is_new = store.last_processed_report(task) != (report_id or scan_date)
    seen = store.mark_actions(task, [a.key for a in acts], scan_date, is_new)
    records = []
    for a in acts:
        rec = {"id": a.id, "key": a.key, "titulo": a.titulo, "acao": a.acao, "threat": a.threat,
               "sev": a.sev, "prioridade": a.prioridade, "familia": a.familia, "hosts": len(a.hosts),
               "cves": len(a.cves), "nvts": len(a.nvts), "team": a.team,
               "teamNome": next((t["nome"] for t in cfg["teams"] if t["id"] == a.team), a.team),
               "status": "Pendente"}
        rec.update(C.sla_fields(a, cfg, base_date))
        s = seen.get(a.key, {})
        rec["reincidente"] = s.get("reincidente", False)
        rec["deteccao"] = s.get("first_seen", base_date.isoformat())
        records.append(rec)
    by = {s: sum(1 for a in acts if a.threat == s) for s in C.SEV}
    abertas = sum(1 for r in records if r["status"] not in ("Corrigido", "Falso positivo"))
    if is_new:
        store.record_snapshot(task, report_id or scan_date, scan_date, {"abertas": abertas, **by})
    feed = {"meta": {"tarefa": parsed["meta"].get("tarefa") or task, "alvo": parsed["meta"].get("alvo", ""),
                     "hostsScan": parsed["meta"].get("hosts_scan", 0), "total": len(parsed["findings"]),
                     "scan": scan_date, "hoje": dt.date.today().isoformat(), "report_id": report_id,
                     "nota": "Importado automaticamente do OpenVAS via GMP."},
            "acoes": records, "evolucao": store.evolution(task)}
    outdir = Path(cfg.get("output_dir", str(ROOT / "data")))
    outdir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in task).strip("-").lower() or "scan"
    (outdir / f"feed-{safe}.json").write_text(json.dumps(feed, ensure_ascii=False, indent=1), encoding="utf-8")
    (outdir / "feed.json").write_text(json.dumps(feed, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"Feed gravado: {len(records)} ações, {feed['meta']['hostsScan']} hosts → {outdir}/feed.json")


def run_once(cfg, args):
    store = None
    if not db_mode():
        from .store import Store
        store = Store(cfg.get("db_path", str(ROOT / "data" / "plataforma.db")))
    try:
        if args.from_file:
            parsed = C.parse_report_file(args.from_file)
            task = parsed["meta"].get("tarefa") or "scan-local"
            if db_mode():
                persist_db(task, None, parsed, cfg)
            else:
                persist_feed(task, None, parsed, cfg, store)
            return
        from .gmp_client import GmpClient
        with GmpClient(cfg["gmp"], cfg["gmp"]["username"], cfg["gmp"]["password"]) as gmp:
            tasks_cfg = cfg.get("tasks") or [t["name"] for t in gmp.list_tasks()]
            for name_or_id in tasks_cfg:
                t = gmp.find_task(name_or_id)
                if not t:
                    log(f"AVISO: tarefa não encontrada no gvmd: {name_or_id!r}")
                    continue
                if args.scan:
                    rid = gmp.start_task(t["id"])
                    log(f"Scan disparado para {t['name']!r} (report {rid}).")
                    continue
                if not t["last_report_id"]:
                    log(f"AVISO: tarefa {t['name']!r} ainda não tem relatório.")
                    continue
                parsed = C._parse_root(gmp.get_report_root(t["last_report_id"]))
                if db_mode():
                    persist_db(t["name"], t["last_report_id"], parsed, cfg)
                else:
                    persist_feed(t["name"], t["last_report_id"], parsed, cfg, store)
    finally:
        if store:
            store.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Importador Greenbone/OpenVAS.")
    ap.add_argument("--config", default=os.environ.get("CONFIG_PATH", str(ROOT / "config" / "config.yaml")))
    ap.add_argument("--scan", action="store_true", help="dispara o(s) scan(s) e sai")
    ap.add_argument("--loop", action="store_true", help="roda continuamente no intervalo configurado")
    ap.add_argument("--from-file", help="consolida um XML local (teste offline)")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    if args.loop:
        interval = int(cfg.get("schedule", {}).get("interval_seconds", 3600))
        log(f"Modo serviço: importando a cada {interval}s ({'banco' if db_mode() else 'feed.json'}).")
        while True:
            try:
                run_once(cfg, args)
            except Exception as e:
                log(f"ERRO na importação: {e!r}")
            time.sleep(interval)
    else:
        run_once(cfg, args)


if __name__ == "__main__":
    main()

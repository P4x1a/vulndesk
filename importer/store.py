"""Persistência leve (SQLite) para continuidade entre scans.

Na Fase 1 isso serve a dois propósitos:
- guardar o histórico de cada importação (para a evolução no tempo);
- detectar reincidência: uma ação cuja "chave" já apareceu num scan anterior.

O acompanhamento completo (responsável, status, prazos editáveis pelas equipes)
é a Fase 2, que amplia este mesmo banco.
"""
from __future__ import annotations
import sqlite3
import datetime as dt

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL,
  report_id TEXT,
  scan_date TEXT,
  imported_at TEXT NOT NULL,
  abertas INTEGER, criticas INTEGER, altas INTEGER, medias INTEGER, baixas INTEGER
);
CREATE TABLE IF NOT EXISTS action_seen (
  task TEXT NOT NULL,
  action_key TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  times_seen INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (task, action_key)
);
"""


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def last_processed_report(self, task: str) -> str | None:
        row = self.conn.execute(
            "SELECT report_id FROM snapshots WHERE task=? ORDER BY id DESC LIMIT 1", (task,)
        ).fetchone()
        return row[0] if row else None

    def mark_actions(self, task: str, keys: list[str], scan_date: str, is_new: bool) -> dict[str, dict]:
        """Devolve, por chave, se é reincidente e desde quando (first_seen).

        Só altera o histórico quando `is_new` (relatório inédito). Reler o mesmo
        relatório (ex.: no ciclo de hora em hora) é somente leitura, para não
        inflar reincidência nem a evolução.
        """
        now = scan_date or dt.date.today().isoformat()
        info: dict[str, dict] = {}
        cur = self.conn.cursor()
        for k in keys:
            row = cur.execute("SELECT first_seen, times_seen FROM action_seen WHERE task=? AND action_key=?", (task, k)).fetchone()
            if not is_new:
                if row:
                    info[k] = {"reincidente": row[1] > 1, "first_seen": row[0]}
                else:
                    info[k] = {"reincidente": False, "first_seen": now}
                continue
            if row:
                info[k] = {"reincidente": True, "first_seen": row[0]}
                cur.execute("UPDATE action_seen SET last_seen=?, times_seen=times_seen+1 WHERE task=? AND action_key=?", (now, task, k))
            else:
                info[k] = {"reincidente": False, "first_seen": now}
                cur.execute("INSERT INTO action_seen(task, action_key, first_seen, last_seen) VALUES (?,?,?,?)", (task, k, now, now))
        if is_new:
            self.conn.commit()
        return info

    def record_snapshot(self, task: str, report_id: str, scan_date: str, counts: dict):
        self.conn.execute(
            "INSERT INTO snapshots(task, report_id, scan_date, imported_at, abertas, criticas, altas, medias, baixas) VALUES (?,?,?,?,?,?,?,?,?)",
            (task, report_id, scan_date, dt.datetime.now().isoformat(timespec="seconds"),
             counts.get("abertas", 0), counts.get("Critical", 0), counts.get("High", 0),
             counts.get("Medium", 0), counts.get("Low", 0)),
        )
        self.conn.commit()

    def evolution(self, task: str, limit: int = 12) -> list[dict]:
        rows = self.conn.execute(
            "SELECT scan_date, abertas, criticas, altas FROM snapshots WHERE task=? ORDER BY id DESC LIMIT ?",
            (task, limit),
        ).fetchall()
        return [{"semana": r[0], "abertas": r[1], "criticas": r[2], "altas": r[3]} for r in reversed(rows)]

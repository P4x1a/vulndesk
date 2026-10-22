"""Cliente GMP (Greenbone Management Protocol).

Conecta ao gvmd — por padrão pelo socket unix, que é como o Greenbone em Docker
(Community Containers) expõe o GMP (/run/gvmd/gvmd.sock) — ou por TLS, quando
configurado. Permite listar tarefas, disparar um scan e baixar o relatório mais
recente em XML, sem export manual pelo GSA.

Requer a biblioteca python-gvm (ver requirements.txt).
"""
from __future__ import annotations
import xml.etree.ElementTree as ET

# Formato de relatório "XML" do GMP (mesmo id do relatório exportado manualmente).
XML_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"


def _connection(conn_cfg: dict):
    kind = (conn_cfg.get("type") or "socket").lower()
    if kind == "socket":
        from gvm.connections import UnixSocketConnection
        return UnixSocketConnection(path=conn_cfg.get("socket_path", "/run/gvmd/gvmd.sock"))
    if kind == "tls":
        from gvm.connections import TLSConnection
        return TLSConnection(hostname=conn_cfg["host"], port=int(conn_cfg.get("port", 9390)))
    raise ValueError(f"Tipo de conexão GMP desconhecido: {kind!r} (use 'socket' ou 'tls').")


class GmpClient:
    """Context manager que autentica no gvmd e expõe as operações usadas na Fase 1."""

    def __init__(self, conn_cfg: dict, username: str, password: str):
        self.conn_cfg = conn_cfg
        self.username = username
        self.password = password
        self._gmp = None

    def __enter__(self):
        # 'latest' usa a classe de protocolo mais recente sem autodetecção de
        # versão — evita o erro "unsupported version of GMP" com gvmd 22.7+.
        from gvm.protocols.latest import Gmp
        from gvm.transforms import EtreeCheckCommandTransform
        self._gmp = Gmp(_connection(self.conn_cfg), transform=EtreeCheckCommandTransform())
        self._gmp.__enter__()
        self._gmp.authenticate(self.username, self.password)
        return self

    def __exit__(self, *exc):
        if self._gmp is not None:
            self._gmp.__exit__(*exc)
        self._gmp = None
        return False

    # ---- tarefas ----
    def list_tasks(self) -> list[dict]:
        resp = self._gmp.get_tasks()
        out = []
        for t in resp.findall("task"):
            last = t.find("last_report/report")
            out.append({
                "id": t.get("id"),
                "name": (t.findtext("name") or "").strip(),
                "status": (t.findtext("status") or "").strip(),
                "last_report_id": last.get("id") if last is not None else None,
            })
        return out

    def find_task(self, name_or_id: str) -> dict | None:
        tasks = self.list_tasks()
        for t in tasks:
            if t["id"] == name_or_id or t["name"] == name_or_id:
                return t
        return None

    def start_task(self, task_id: str) -> str:
        """Dispara um scan. Devolve o id do report iniciado (quando informado)."""
        resp = self._gmp.start_task(task_id)
        rid = resp.find("report_id")
        return rid.text if rid is not None else ""

    # ---- relatórios ----
    def latest_report_id(self, task_id: str) -> str | None:
        t = next((x for x in self.list_tasks() if x["id"] == task_id), None)
        return t["last_report_id"] if t else None

    def get_report_root(self, report_id: str):
        """Baixa o relatório em XML e devolve o elemento <report> pronto para o parser."""
        resp = self._gmp.get_report(
            report_id,
            report_format_id=XML_REPORT_FORMAT_ID,
            filter_string="apply_overrides=0 levels=chml rows=-1 min_qod=70",
            ignore_pagination=True,
            details=True,
        )
        # Estrutura: <get_reports_response><report id=..><report>...</report></report>
        outer = resp.find("report")
        if outer is None:
            raise RuntimeError("Resposta do GMP sem elemento <report>.")
        return outer

    def get_report_xml(self, report_id: str) -> str:
        return ET.tostring(self.get_report_root(report_id), encoding="unicode")

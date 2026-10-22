"""Modelo de dados da plataforma (Fase 2).

Guarda as ações de correção com as tratativas das equipes (status, responsável,
observação), o histórico de alterações e os snapshots para a evolução. Substitui
as planilhas: é a fonte única, multiusuário e com trilha de auditoria.
"""
from __future__ import annotations
import datetime as dt
from sqlalchemy import String, Integer, Float, Boolean, Date, DateTime, Text, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

STATUSES = ["Pendente", "Em andamento", "Corrigido", "Risco aceito", "Falso positivo"]
STATUS_FECHADO = {"Corrigido", "Risco aceito", "Falso positivo"}


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)        # ex.: 'infra'
    nome: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(200), default="")
    cc: Mapped[str] = mapped_column(String(400), default="")
    password_hash: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(20), default="equipe")      # 'equipe' | 'admin'


class Action(Base):
    __tablename__ = "actions"
    __table_args__ = (UniqueConstraint("task", "action_key", name="uq_task_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task: Mapped[str] = mapped_column(String(200), index=True)
    action_key: Mapped[str] = mapped_column(String(300), index=True)
    codigo: Mapped[str] = mapped_column(String(12), default="")          # A-001 (recalculado por import)

    # Campos vindos do scan (atualizados a cada importação)
    titulo: Mapped[str] = mapped_column(Text, default="")
    acao: Mapped[str] = mapped_column(Text, default="")
    threat: Mapped[str] = mapped_column(String(10), default="")          # Critical/High/Medium/Low
    sev: Mapped[float] = mapped_column(Float, default=0.0)
    prioridade: Mapped[str] = mapped_column(String(4), default="")
    familia: Mapped[str] = mapped_column(String(120), default="")
    produto_nome: Mapped[str] = mapped_column(String(200), default="")
    produto_key: Mapped[str] = mapped_column(String(200), default="")
    hosts_count: Mapped[int] = mapped_column(Integer, default=0)
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    portas: Mapped[dict] = mapped_column(JSON, default=dict)
    cves: Mapped[list] = mapped_column(JSON, default=list)
    nvts: Mapped[list] = mapped_column(JSON, default=list)
    resumo: Mapped[str] = mapped_column(Text, default="")
    solucao: Mapped[str] = mapped_column(Text, default="")

    # Atribuição (auto por regras; team é o efetivo, editável)
    team_auto: Mapped[str] = mapped_column(String(32), default="")
    team: Mapped[str] = mapped_column(String(32), index=True, default="")

    # Tratativa das equipes (NÃO sobrescrita pela importação)
    status: Mapped[str] = mapped_column(String(20), default="Pendente", index=True)
    responsavel: Mapped[str] = mapped_column(String(120), default="")
    observacao: Mapped[str] = mapped_column(Text, default="")

    # Prazo / SLA / detecção
    sla_dias: Mapped[int] = mapped_column(Integer, default=90)
    prazo: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    deteccao: Mapped[dt.date | None] = mapped_column(Date, nullable=True)   # primeira vez visto

    # Estado de ciclo de vida
    reincidente: Mapped[bool] = mapped_column(Boolean, default=False)
    vezes_visto: Mapped[int] = mapped_column(Integer, default=1)
    ativo: Mapped[bool] = mapped_column(Boolean, default=True)              # presente no último scan
    last_report_id: Mapped[str] = mapped_column(String(80), default="")
    last_seen: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    resolvido_em: Mapped[dt.date | None] = mapped_column(Date, nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    history: Mapped[list["History"]] = relationship(back_populates="action", cascade="all, delete-orphan")


class History(Base):
    __tablename__ = "action_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("actions.id", ondelete="CASCADE"), index=True)
    quando: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    quem: Mapped[str] = mapped_column(String(120), default="sistema")       # equipe que alterou, ou 'sistema'
    campo: Mapped[str] = mapped_column(String(40), default="")
    de: Mapped[str] = mapped_column(Text, default="")
    para: Mapped[str] = mapped_column(Text, default="")
    action: Mapped["Action"] = relationship(back_populates="history")


class NotifyLog(Base):
    """Registro de notificações já enviadas, para não repetir o mesmo alerta.
    kind: 'novo' (nova crítica/alta atribuída) | 'prazo' (perto de vencer) | 'vencido'."""
    __tablename__ = "notify_log"
    __table_args__ = (UniqueConstraint("action_id", "kind", name="uq_notify"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="")
    quando: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task: Mapped[str] = mapped_column(String(200), index=True)
    report_id: Mapped[str] = mapped_column(String(80), default="")
    scan_date: Mapped[str] = mapped_column(String(10), default="")
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    hosts_scan: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    alvo: Mapped[str] = mapped_column(String(300), default="")
    abertas: Mapped[int] = mapped_column(Integer, default=0)
    corrigidas: Mapped[int] = mapped_column(Integer, default=0)
    criticas: Mapped[int] = mapped_column(Integer, default=0)
    altas: Mapped[int] = mapped_column(Integer, default=0)
    medias: Mapped[int] = mapped_column(Integer, default=0)
    baixas: Mapped[int] = mapped_column(Integer, default=0)

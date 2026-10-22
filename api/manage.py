"""Administração por linha de comando.

Uso (dentro do container da api ou com DATABASE_URL apontando para o banco):
  python -m api.manage list
  python -m api.manage set-password <equipe> <nova-senha>
"""
from __future__ import annotations
import sys
from .db import SessionLocal, Base, engine
from . import models, auth


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        if not argv or argv[0] == "list":
            for t in db.query(models.Team).all():
                print(f"{t.id:10} {t.role:7} {t.nome}")
        elif argv[0] == "set-password" and len(argv) == 3:
            t = db.get(models.Team, argv[1])
            if not t:
                print(f"Equipe não encontrada: {argv[1]}")
                return 1
            t.password_hash = auth.hash_password(argv[2])
            db.commit()
            print(f"Senha atualizada para a equipe {argv[1]}.")
        else:
            print(__doc__)
            return 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

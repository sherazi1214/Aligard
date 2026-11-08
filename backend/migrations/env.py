"""Alembic environment: DB URL settings (.env) se aata hai, alembic.ini mein nahi."""
import sys
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine

# Project root sys.path mein: bina PYTHONPATH ke `alembic ...` chale ("No module named backend" fix)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app import models  # noqa: F401  (tables register karne ke liye)
from backend.app.config import get_settings
from backend.app.db import Base

target_metadata = Base.metadata


def run_migrations() -> None:
    engine = create_engine(get_settings().database_url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations()

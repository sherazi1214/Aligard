"""Database connection (SQLAlchemy 2.0). Models backend/app/models.py mein Base se bante hain."""
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.app.config import get_settings

log = logging.getLogger("aliguard.db")


class Base(DeclarativeBase):
    """Saray tables isi se inherit karenge."""


# pool_pre_ping: toot chuki connection khud detect karke dobara banata hai
_url = get_settings().database_url
if _url.startswith("sqlite"):
    # Sirf tests: in-memory SQLite mein ek hi connection share honi chahiye
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        _url, connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
else:
    engine = create_engine(_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    """FastAPI dependency: har request ko apni session, aur end pe band."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db() -> bool:
    """Health check ke liye. Error ki tafseel bahar nahi jati, sirf log hoti hai."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        log.exception("Database check fail")
        return False

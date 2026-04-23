"""
src/database/db.py
Database engine, session management, and initialization.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from typing import Generator
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from src.database.models import Base
from src.utils.logger import get_logger

logger = get_logger("cti.database")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/cti.db")

# SQLite-specific: enable WAL mode and foreign keys
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    pool_pre_ping=True,
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all tables. Call once at startup."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized", )


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Context manager for database sessions with automatic rollback on error."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Database error, rolling back: {e}")
        raise
    finally:
        db.close()


def get_db_session() -> Session:
    """Dependency for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

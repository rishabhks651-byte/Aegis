"""SQLAlchemy engine, session factory, and declarative Base."""

from __future__ import annotations

import contextlib
from typing import Any, Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from aegis.persistence import DATABASE_URL


class Base(DeclarativeBase):
    pass


# check_same_thread=False required for concurrency tests with SQLite
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

_engine = create_engine(DATABASE_URL, echo=False, connect_args=_connect_args)

# Enable FK enforcement for SQLite
@event.listens_for(_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    import sqlite3
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


_SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)


def get_engine() -> Any:
    return _engine


def get_session() -> Session:
    return _SessionFactory()


@contextlib.contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables."""
    Base.metadata.create_all(bind=_engine)


def drop_db() -> None:
    """Drop all tables (testing only)."""
    Base.metadata.drop_all(bind=_engine)


def rebuild_db() -> None:
    """Drop and recreate all tables (testing only)."""
    drop_db()
    init_db()

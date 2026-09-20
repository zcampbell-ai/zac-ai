"""SQLAlchemy engine/session construction for Zac State (D026).

Owns connection lifecycle only. No entity, boundary, or versioning logic
lives here - see `zacai.state` for the schema and
`zacai.state_repository` for the boundary-enforcing access functions that
actually read and write it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.config import get_settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Lazily construct the process-wide engine from `Settings.database_url`."""
    global _engine
    if _engine is None:
        _engine = create_engine(get_settings().database_url, future=True)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), future=True, expire_on_commit=False)
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Commit on success, roll back and re-raise on any exception.

    Callers that want explicit control over transaction boundaries (e.g.
    tests exercising concurrency, or a caller composing several repository
    calls into one transaction) may construct a `Session` directly via
    `get_session_factory()` instead.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

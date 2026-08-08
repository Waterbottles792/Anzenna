"""CRUD helpers for the tables in docs/contracts/DB_SCHEMA.sql.

Plain functions taking a SQLAlchemy Session, not a repository class per
table -- there's one implementation per table, nothing to swap, so a class
hierarchy would just be ceremony around what's already here. Phase 7's
FastAPI layer calls these; they're written and tested independently of it
(api/test_db.py, against a real Postgres).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from api.models import ApiKey, Org, ScanLog, UsageCounter, User

TEXT_PREVIEW_MAX_CHARS = 100


def make_session_factory(database_url: str) -> sessionmaker[Session]:
    """Build a sessionmaker bound to `database_url`. Connection pooling is
    SQLAlchemy's `create_engine` default -- no custom pool config needed at
    this scale."""
    engine = create_engine(database_url, future=True)
    return sessionmaker(bind=engine, future=True)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest. DB_SCHEMA.sql/API_CONTRACT.md require storing a
    hash, never plaintext. No per-row salt: API keys are already
    high-entropy random tokens (unlike passwords), so a deterministic hash
    is safe and lets Phase 7's auth do a simple indexed equality lookup by
    hash instead of scanning every row to check a salted hash."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# --- orgs -------------------------------------------------------------------

def create_org(session: Session, name: str, *, stripe_customer_id: Optional[str] = None) -> Org:
    org = Org(name=name, stripe_customer_id=stripe_customer_id)
    session.add(org)
    session.flush()
    return org


def get_org(session: Session, org_id: uuid.UUID) -> Optional[Org]:
    return session.get(Org, org_id)


# --- users --------------------------------------------------------------

def create_user(session: Session, org_id: uuid.UUID, email: str) -> User:
    user = User(org_id=org_id, email=email)
    session.add(user)
    session.flush()
    return user


# --- api_keys -----------------------------------------------------------

def create_api_key(session: Session, org_id: uuid.UUID, raw_key: str, *, label: Optional[str] = None) -> ApiKey:
    key = ApiKey(org_id=org_id, key_hash=hash_api_key(raw_key), key_prefix=raw_key[:8], label=label)
    session.add(key)
    session.flush()
    return key


def get_api_key_by_raw_key(session: Session, raw_key: str) -> Optional[ApiKey]:
    """Phase 7's auth middleware: hash the incoming key and look it up.
    Returns the row (revoked or not) or None if it doesn't exist at all --
    the caller decides what a revoked key means for the request."""
    return session.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key)))


def revoke_api_key(session: Session, api_key_id: uuid.UUID) -> Optional[ApiKey]:
    key = session.get(ApiKey, api_key_id)
    if key is not None and key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        session.flush()
    return key


def list_api_keys(session: Session, org_id: uuid.UUID) -> list[ApiKey]:
    stmt = select(ApiKey).where(ApiKey.org_id == org_id).order_by(ApiKey.created_at.desc())
    return list(session.scalars(stmt))


# --- scan_logs ------------------------------------------------------------

def log_scan(
    session: Session,
    *,
    org_id: uuid.UUID,
    api_key_id: uuid.UUID,
    direction: str,
    verdict: str,
    risk_score: int,
    categories: Optional[list[str]] = None,
    latency_ms: Optional[int] = None,
    text_preview: Optional[str] = None,
) -> ScanLog:
    log = ScanLog(
        org_id=org_id,
        api_key_id=api_key_id,
        direction=direction,
        verdict=verdict,
        risk_score=risk_score,
        categories=categories,
        latency_ms=latency_ms,
        text_preview=text_preview[:TEXT_PREVIEW_MAX_CHARS] if text_preview else None,
    )
    session.add(log)
    session.flush()
    return log


def list_scan_logs(
    session: Session, org_id: uuid.UUID, *, limit: int = 50, cursor: Optional[datetime] = None
) -> list[ScanLog]:
    """GET /v1/logs?limit=&cursor= per API_CONTRACT.md -- `cursor` is the
    `created_at` of the last row from the previous page (keyset pagination,
    matches idx_scan_logs_org_created's (org_id, created_at DESC) shape)."""
    stmt = select(ScanLog).where(ScanLog.org_id == org_id)
    if cursor is not None:
        stmt = stmt.where(ScanLog.created_at < cursor)
    stmt = stmt.order_by(ScanLog.created_at.desc()).limit(limit)
    return list(session.scalars(stmt))


# --- usage_counters -------------------------------------------------------

def increment_usage(session: Session, org_id: uuid.UUID, period_start: date, *, by: int = 1) -> UsageCounter:
    """Atomic get-or-create-and-bump via Postgres UPSERT (INSERT ... ON
    CONFLICT DO UPDATE) -- a read-then-write increment would race under
    concurrent scan requests hitting the same (org_id, period_start) row."""
    stmt = pg_insert(UsageCounter).values(org_id=org_id, period_start=period_start, scan_count=by)
    stmt = stmt.on_conflict_do_update(
        index_elements=[UsageCounter.org_id, UsageCounter.period_start],
        set_={"scan_count": UsageCounter.scan_count + by},
    )
    session.execute(stmt)
    session.flush()
    # populate_existing: the upsert is a raw Core statement, so if this row
    # was already loaded into the session's identity map (e.g. an earlier
    # increment_usage call this session), a plain session.get() would return
    # that now-stale cached object instead of the just-updated row.
    counter = session.get(UsageCounter, (org_id, period_start), populate_existing=True)
    assert counter is not None
    return counter


def get_usage(session: Session, org_id: uuid.UUID, period_start: date) -> int:
    """GET /v1/usage per API_CONTRACT.md. Returns 0 for a period with no
    counter row yet, rather than None -- 0 usage is the correct answer, not
    a missing one."""
    counter = session.get(UsageCounter, (org_id, period_start))
    return counter.scan_count if counter is not None else 0

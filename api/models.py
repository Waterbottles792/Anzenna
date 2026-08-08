"""SQLAlchemy ORM models matching docs/contracts/DB_SCHEMA.sql exactly.

That file is the source of truth (per docs/plan.md, contract files "never
change after Phase 0"); these models mirror it column-for-column so
api/db.py and Phase 7's FastAPI layer have a typed interface to it. The
actual DDL applied to a real database comes from alembic/versions/, which
executes DB_SCHEMA.sql verbatim rather than re-deriving it from these
models -- see that migration's docstring for why.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy import ARRAY, Date, DateTime, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=sa.func.gen_random_uuid())
    name: Mapped[str] = mapped_column(Text, nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(Text)
    plan: Mapped[str] = mapped_column(Text, nullable=False, server_default="free")  # free | pro | scale
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa.func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=sa.func.gen_random_uuid())
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa.func.now())


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=sa.func.gen_random_uuid())
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)  # store hash, never plaintext
    key_prefix: Mapped[str] = mapped_column(Text, nullable=False)  # first 8 chars, shown in dashboard
    label: Mapped[str | None] = mapped_column(Text)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa.func.now())


class ScanLog(Base):
    __tablename__ = "scan_logs"
    __table_args__ = (Index("idx_scan_logs_org_created", "org_id", sa.text("created_at DESC")),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=sa.func.gen_random_uuid())
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("api_keys.id"), nullable=False)
    direction: Mapped[str] = mapped_column(Text, nullable=False)  # input | output
    verdict: Mapped[str] = mapped_column(Text, nullable=False)  # allow | flag | block
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    categories: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    # Never the raw scanned text long-term (privacy) -- truncated preview only.
    text_preview: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=sa.func.now())


class UsageCounter(Base):
    __tablename__ = "usage_counters"

    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), primary_key=True)
    period_start: Mapped[date] = mapped_column(Date, primary_key=True)
    scan_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

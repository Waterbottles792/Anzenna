"""initial schema from DB_SCHEMA.sql

Revision ID: 8a3d2df55551
Revises:
Create Date: 2026-08-09 01:44:17.235101

Executes docs/contracts/DB_SCHEMA.sql verbatim rather than re-deriving DDL
from api/models.py (e.g. via autogenerate). DB_SCHEMA.sql is the contract's
source of truth (docs/plan.md: contract files "never change after Phase 0"),
so this migration just applies it -- guarantees the two never drift, and
"schema applies cleanly to a fresh Postgres DB" (Phase 6's Definition of
Done) is trivially true since it IS that file.
"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8a3d2df55551'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA_SQL_PATH = Path(__file__).resolve().parents[3] / "docs" / "contracts" / "DB_SCHEMA.sql"

# Reverse of DB_SCHEMA.sql's CREATE TABLE order, so foreign keys drop cleanly.
_TABLES_NEWEST_FIRST = ["usage_counters", "scan_logs", "api_keys", "users", "orgs"]


def upgrade() -> None:
    op.execute(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))


def downgrade() -> None:
    for table in _TABLES_NEWEST_FIRST:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")

# api/ — DB layer (Phase 6) + FastAPI service (Phase 7, not built yet)

Phase 6 only: SQLAlchemy models + CRUD helpers against
`docs/contracts/DB_SCHEMA.sql`, which is the source of truth (contract files
"never change after Phase 0" per `docs/plan.md`).

- `models.py` — ORM models mirroring `DB_SCHEMA.sql` column-for-column.
- `db.py` — plain CRUD functions (`create_org`, `create_api_key`, `log_scan`,
  `increment_usage`, ...) taking a SQLAlchemy `Session`. Phase 7 calls these;
  they're tested independently of it.
- `alembic/` — migrations. The initial migration executes `DB_SCHEMA.sql`
  verbatim (`op.execute(path.read_text())`) rather than re-deriving DDL from
  `models.py`, so the two can never drift.

Requires the `db` extra: `pip install -e ".[db]"` (installs SQLAlchemy,
Alembic, `psycopg`).

## Local Postgres

Any local or containerized Postgres works. Quickest path (Docker):

```bash
docker run -d --name anzenna-pg \
  -e POSTGRES_USER=anzenna -e POSTGRES_PASSWORD=anzenna -e POSTGRES_DB=anzenna_test \
  -p 55432:5432 postgres:16-alpine

export DATABASE_URL="postgresql+psycopg://anzenna:anzenna@localhost:55432/anzenna_test"
alembic upgrade head
```

`alembic` (run from the repo root) reads `DATABASE_URL` from the environment
-- `alembic.ini`'s `sqlalchemy.url` is intentionally left blank, so no
connection string lives in a committed file.

## Running the tests

```bash
export ANZENNA_TEST_DATABASE_URL="postgresql+psycopg://anzenna:anzenna@localhost:55432/anzenna_test"
pytest api/test_db.py
```

`api/test_db.py` skips itself entirely if neither `ANZENNA_TEST_DATABASE_URL`
nor `DATABASE_URL` is set -- the rest of the suite (`engine/`, `sdks/`) never
needs Postgres. CI runs these against a real `postgres:16-alpine` service
container (see `.github/workflows/ci.yml`).

Each test runs inside a `SAVEPOINT` that's rolled back in teardown, so tests
never see each other's data and the DB needs no manual cleanup between runs.

## New migration

```bash
export DATABASE_URL=...
alembic revision -m "describe the change"   # hand-write it, or:
alembic revision --autogenerate -m "..."    # diff against api/models.py
alembic upgrade head
```

If a change touches `DB_SCHEMA.sql`, update that file first (it's the
contract) -- `api/models.py` should always match it exactly.

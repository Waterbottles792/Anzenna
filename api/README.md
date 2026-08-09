# api/ — DB layer (Phase 6) + FastAPI service (Phase 7)

SQLAlchemy models + CRUD helpers against `docs/contracts/DB_SCHEMA.sql`
(the source of truth -- contract files "never change after Phase 0" per
`docs/plan.md`), plus the FastAPI service that sits on top of them.

- `models.py` — ORM models mirroring `DB_SCHEMA.sql` column-for-column.
- `db.py` — plain CRUD functions (`create_org`, `create_api_key`, `log_scan`,
  `increment_usage`, ...) taking a SQLAlchemy `Session`. `main.py` calls
  these; they're tested independently of it (`test_db.py`).
- `alembic/` — migrations. The initial migration executes `DB_SCHEMA.sql`
  verbatim (`op.execute(path.read_text())`) rather than re-deriving DDL from
  `models.py`, so the two can never drift.
- `main.py` — FastAPI app implementing `docs/contracts/API_CONTRACT.md`'s
  `POST /v1/scan` and `GET /v1/usage`: API-key auth (hash + lookup against
  `api_keys`), a per-key in-memory requests/second limiter, monthly usage-cap
  enforcement per `PLAN_LIMITS`, and scan logging. Calls `engine.pipeline.scan`
  -- the only engine dependency, per `DETECTION_INTERFACE.md`. The contract's
  session-auth dashboard endpoints (`/v1/keys`, `/v1/logs`) aren't here yet;
  they need Phase 9's auth provider first.

Requires the `db` and `api` extras: `pip install -e ".[db,api]"` (installs
SQLAlchemy, Alembic, `psycopg`, FastAPI, Uvicorn).

## Running the service

```bash
export DATABASE_URL=...   # see "Local Postgres" below
uvicorn api.main:app --reload
```

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
pytest api/test_db.py api/test_main.py
```

Both files skip themselves entirely if neither `ANZENNA_TEST_DATABASE_URL`
nor `DATABASE_URL` is set -- the rest of the suite (`engine/`, `sdks/`) never
needs Postgres. CI runs these against a real `postgres:16-alpine` service
container (see `.github/workflows/ci.yml`). `test_main.py` monkeypatches
`engine.pipeline.scan` to a fixed result -- it only tests the API layer
(auth, validation, usage caps, rate limiting, logging), not the engine's own
detection logic (already covered by `engine/test_pipeline.py`).

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

# api/ — DB layer (Phase 6) + FastAPI service (Phase 7) + billing (Phase 8)

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
  they need Phase 9's auth provider first. Also hosts the Phase 8 billing
  routes below, which aren't part of `API_CONTRACT.md`.
- `billing.py` — Stripe: `ensure_stripe_customer`/`create_checkout_session`
  (org upgrade flow), `report_usage`/`report_usage_for_all_orgs` (metered
  usage records, call the batch variant from a scheduler -- provisioning
  that scheduler is a Phase 12 infra concern, not this module's job), and
  `handle_webhook_event` (applies subscription created/updated/deleted
  events to `orgs.plan`). Every Stripe SDK call takes an injectable
  `stripe_module` param, so `test_billing.py` runs against a mocked SDK with
  zero network calls -- no live Stripe account needed to develop or test
  this. `main.py` exposes it as `POST /v1/billing/checkout` and
  `POST /webhooks/stripe`.

Requires the `db`, `api`, and `billing` extras: `pip install -e ".[db,api,billing]"`
(installs SQLAlchemy, Alembic, `psycopg`, FastAPI, Uvicorn, `stripe`).

### Going live with real Stripe

Nothing in this repo talks to a real Stripe account -- `billing.py` is built
and tested entirely against a mocked SDK. To actually take payments:

1. In the Stripe dashboard (test mode first), create two recurring metered
   prices, one for `pro` and one for `scale`. Set their ids as
   `STRIPE_PRICE_ID_PRO`/`STRIPE_PRICE_ID_SCALE` (see `.env.example`).
2. Set `STRIPE_SECRET_KEY` (dashboard) and `STRIPE_WEBHOOK_SECRET` (from
   `stripe listen --forward-to localhost:8000/webhooks/stripe`, or the
   dashboard once a production endpoint exists).
3. Forward webhooks locally with the Stripe CLI (`stripe listen ...` above)
   while testing a real checkout in test mode.
4. Point a scheduler at `billing.report_usage_for_all_orgs(session, period_start)`
   once a day, per plan.md's Phase 8 task 2.

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
pytest api/test_db.py api/test_main.py api/test_billing.py
```

All three files skip themselves entirely if neither `ANZENNA_TEST_DATABASE_URL`
nor `DATABASE_URL` is set -- the rest of the suite (`engine/`, `sdks/`) never
needs Postgres. CI runs these against a real `postgres:16-alpine` service
container (see `.github/workflows/ci.yml`). `test_main.py` monkeypatches
`engine.pipeline.scan` to a fixed result -- it only tests the API layer
(auth, validation, usage caps, rate limiting, logging), not the engine's own
detection logic (already covered by `engine/test_pipeline.py`). Likewise
`test_billing.py` mocks the Stripe SDK -- it tests `billing.py`'s logic, not
Stripe itself.

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

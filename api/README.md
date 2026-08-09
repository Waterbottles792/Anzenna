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
- `billing.py` — Dodo Payments (a Merchant of Record, not a raw payment
  processor -- it handles VAT/GST/sales-tax compliance itself; used instead
  of Stripe because Stripe has been invite-only for India-based businesses
  since May 2024): `ensure_dodo_customer`/`create_checkout_session` (org
  upgrade flow), `report_scan_usage` (one metered usage event per scan,
  called from `main.py` right after each scan is logged -- Dodo's
  usage-events API ingests per-unit events deduped by id, unlike Stripe's
  usage records which `set` a period's cumulative total, so there's no
  daily batch job here), and `handle_webhook_event` (applies subscription
  webhook events to `orgs.plan`, keyed off the subscription's `status`
  field so every event type -- active/renewed/cancelled/on_hold/... -- is
  handled the same way). Every Dodo SDK call takes an injectable `client`
  param, so `test_billing.py` runs against a mocked SDK with zero network
  calls -- no live Dodo account needed to develop or test this. `main.py`
  exposes it as `POST /v1/billing/checkout` and `POST /webhooks/dodo-payments`.
  The Dodo customer id is persisted into `orgs.stripe_customer_id` -- that
  column name is frozen (`DB_SCHEMA.sql`'s a contract), reused rather than
  added to.

Requires the `db`, `api`, and `billing` extras: `pip install -e ".[db,api,billing]"`
(installs SQLAlchemy, Alembic, `psycopg`, FastAPI, Uvicorn, `dodopayments`).

### Going live with real Dodo Payments

Nothing in this repo talks to a real Dodo Payments account -- `billing.py`
is built and tested entirely against a mocked SDK. To actually take
payments:

1. In the Dodo Payments dashboard (test mode first), create two products,
   one for `pro` and one for `scale`, with a usage-based/metered price tied
   to a "scan" meter. Set their ids as `DODO_PRODUCT_ID_PRO`/
   `DODO_PRODUCT_ID_SCALE` (see `.env.example`).
2. Set `DODO_PAYMENTS_API_KEY` and `DODO_PAYMENTS_WEBHOOK_KEY` (dashboard),
   and `DODO_PAYMENTS_ENVIRONMENT=test_mode` while testing.
3. Point the dashboard's webhook endpoint at
   `POST /webhooks/dodo-payments` for the subscription events, or forward
   locally with their CLI/ngrok during development.
4. Every `POST /v1/scan` on a paying org already reports usage in real time
   via `report_scan_usage` -- no scheduler to provision, unlike a
   Stripe-shaped integration.

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
`test_billing.py` mocks the Dodo Payments SDK -- it tests `billing.py`'s
logic, not Dodo Payments itself.

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

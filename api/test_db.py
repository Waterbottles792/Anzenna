"""Tests for api/db.py's CRUD helpers, against a real Postgres database.

Requires ANZENNA_TEST_DATABASE_URL (or DATABASE_URL) pointing at a Postgres
DB with docs/contracts/DB_SCHEMA.sql already applied (`alembic upgrade
head`). Skips the whole module if neither is set, so the rest of the suite
(engine/, sdks/) stays runnable with zero infra -- see api/README.md for how
to stand one up locally.

Each test runs inside a SAVEPOINT that's rolled back in teardown, so tests
never see each other's data and never need manual cleanup.
"""

import os
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine

pytest.importorskip("sqlalchemy")

DATABASE_URL = os.environ.get("ANZENNA_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    pytest.skip(
        "set ANZENNA_TEST_DATABASE_URL (or DATABASE_URL) to a Postgres DB "
        "with DB_SCHEMA.sql applied to run api/test_db.py -- see api/README.md",
        allow_module_level=True,
    )

from api import db  # noqa: E402
from api.models import ApiKey, ScanLog  # noqa: E402


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL, future=True)
    connection = engine.connect()
    outer_txn = connection.begin()
    from sqlalchemy.orm import Session

    sess = Session(bind=connection, future=True)
    sess.begin_nested()  # SAVEPOINT: every test's writes roll back together

    yield sess

    sess.close()
    outer_txn.rollback()
    connection.close()
    engine.dispose()


@pytest.fixture()
def org(session):
    return db.create_org(session, "Acme Corp")


@pytest.fixture()
def api_key(session, org):
    return db.create_api_key(session, org.id, "sk-anzenna-test-raw-key-value", label="ci")


def test_create_org(session):
    org = db.create_org(session, "Acme Corp", stripe_customer_id="cus_123")
    assert isinstance(org.id, uuid.UUID)
    assert org.plan == "free"
    assert org.stripe_customer_id == "cus_123"
    assert db.get_org(session, org.id).name == "Acme Corp"


def test_get_org_missing_returns_none(session):
    assert db.get_org(session, uuid.uuid4()) is None


def test_create_user(session, org):
    user = db.create_user(session, org.id, "jane@example.com")
    assert user.org_id == org.id
    assert user.email == "jane@example.com"


def test_hash_api_key_is_deterministic_sha256():
    assert db.hash_api_key("abc") == db.hash_api_key("abc")
    assert db.hash_api_key("abc") != db.hash_api_key("xyz")
    assert len(db.hash_api_key("abc")) == 64  # sha256 hex digest


def test_create_api_key_stores_hash_not_plaintext(session, org):
    raw_key = "sk-anzenna-supersecretvalue"
    key = db.create_api_key(session, org.id, raw_key, label="prod")
    assert key.key_hash != raw_key
    assert key.key_hash == db.hash_api_key(raw_key)
    assert key.key_prefix == raw_key[:8]
    assert key.revoked_at is None


def test_get_api_key_by_raw_key_roundtrip(session, org, api_key):
    found = db.get_api_key_by_raw_key(session, "sk-anzenna-test-raw-key-value")
    assert found is not None
    assert found.id == api_key.id


def test_get_api_key_by_raw_key_wrong_key_returns_none(session, org, api_key):
    assert db.get_api_key_by_raw_key(session, "wrong-key") is None


def test_revoke_api_key(session, api_key):
    assert api_key.revoked_at is None
    revoked = db.revoke_api_key(session, api_key.id)
    assert revoked.revoked_at is not None
    assert revoked.revoked_at.tzinfo is not None


def test_revoke_api_key_missing_returns_none(session):
    assert db.revoke_api_key(session, uuid.uuid4()) is None


def test_list_api_keys_ordered_newest_first(session, org):
    # Explicit created_at, not db.create_api_key()'s now()-based default:
    # Postgres's now() is frozen for the whole transaction, and every test
    # here runs inside one shared transaction (see the `session` fixture),
    # so two real inserts a moment apart would get an *identical*
    # created_at -- this pins the ordering deterministically instead.
    now = datetime.now(timezone.utc)
    older = ApiKey(org_id=org.id, key_hash=db.hash_api_key("k1"), key_prefix="sk-key-o", created_at=now - timedelta(minutes=1))
    newer = ApiKey(org_id=org.id, key_hash=db.hash_api_key("k2"), key_prefix="sk-key-n", created_at=now)
    session.add_all([older, newer])
    session.flush()

    keys = db.list_api_keys(session, org.id)
    assert [k.id for k in keys] == [newer.id, older.id]


def test_log_scan_truncates_preview(session, org, api_key):
    long_text = "x" * 500
    log = db.log_scan(
        session,
        org_id=org.id,
        api_key_id=api_key.id,
        direction="input",
        verdict="block",
        risk_score=95,
        categories=["prompt_injection", "jailbreak"],
        latency_ms=42,
        text_preview=long_text,
    )
    assert log.risk_score == 95
    assert log.categories == ["prompt_injection", "jailbreak"]
    assert len(log.text_preview) == db.TEXT_PREVIEW_MAX_CHARS


def test_log_scan_without_preview(session, org, api_key):
    log = db.log_scan(session, org_id=org.id, api_key_id=api_key.id, direction="output", verdict="allow", risk_score=0)
    assert log.text_preview is None
    assert log.categories is None


def test_list_scan_logs_newest_first_and_paginated(session, org, api_key):
    # Explicit created_at -- see the comment in test_list_api_keys_ordered_newest_first.
    base = datetime.now(timezone.utc)
    for i in range(3):
        log = ScanLog(
            org_id=org.id,
            api_key_id=api_key.id,
            direction="input",
            verdict="allow",
            risk_score=i,
            created_at=base + timedelta(seconds=i),
        )
        session.add(log)
    session.flush()

    page1 = db.list_scan_logs(session, org.id, limit=2)
    assert len(page1) == 2
    assert page1[0].risk_score == 2
    assert page1[1].risk_score == 1

    page2 = db.list_scan_logs(session, org.id, limit=2, cursor=page1[-1].created_at)
    assert len(page2) == 1
    assert page2[0].risk_score == 0


def test_list_scan_logs_only_returns_requested_org(session, org, api_key):
    other_org = db.create_org(session, "Other Org")
    other_key = db.create_api_key(session, other_org.id, "sk-other-org-key")
    db.log_scan(session, org_id=org.id, api_key_id=api_key.id, direction="input", verdict="allow", risk_score=1)
    db.log_scan(session, org_id=other_org.id, api_key_id=other_key.id, direction="input", verdict="allow", risk_score=2)

    logs = db.list_scan_logs(session, org.id)
    assert len(logs) == 1
    assert logs[0].org_id == org.id


def test_increment_usage_creates_and_bumps(session, org):
    period = date.today().replace(day=1)
    counter = db.increment_usage(session, org.id, period)
    assert counter.scan_count == 1

    counter = db.increment_usage(session, org.id, period)
    assert counter.scan_count == 2

    counter = db.increment_usage(session, org.id, period, by=5)
    assert counter.scan_count == 7


def test_get_usage_no_counter_row_returns_zero(session, org):
    assert db.get_usage(session, org.id, date.today()) == 0


def test_get_usage_matches_increment(session, org):
    period = date.today().replace(day=1)
    db.increment_usage(session, org.id, period, by=3)
    assert db.get_usage(session, org.id, period) == 3


def test_usage_counters_are_isolated_per_period(session, org):
    today = date.today().replace(day=1)
    last_month = (today - timedelta(days=1)).replace(day=1)

    db.increment_usage(session, org.id, today, by=2)
    db.increment_usage(session, org.id, last_month, by=9)

    assert db.get_usage(session, org.id, today) == 2
    assert db.get_usage(session, org.id, last_month) == 9

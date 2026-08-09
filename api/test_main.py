"""Integration tests for api/main.py, against a real Postgres database.

Same skip/fixture pattern as api/test_db.py: requires
ANZENNA_TEST_DATABASE_URL (or DATABASE_URL) with DB_SCHEMA.sql applied, and
runs each test inside a rolled-back SAVEPOINT. `engine.pipeline.scan` is
monkeypatched to a fixed result -- the engine's own correctness is covered
by engine/test_pipeline.py; these tests only exercise the API layer wired
around it (auth, body validation, usage caps, rate limiting, logging).
"""

import os
import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import create_engine

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

DATABASE_URL = os.environ.get("ANZENNA_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    pytest.skip(
        "set ANZENNA_TEST_DATABASE_URL (or DATABASE_URL) to a Postgres DB "
        "with DB_SCHEMA.sql applied to run api/test_main.py -- see api/README.md",
        allow_module_level=True,
    )

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from api import db, main  # noqa: E402
from engine.pipeline import ScanResult  # noqa: E402

FAKE_ALLOW = ScanResult(
    verdict="allow", risk_score=0.0, categories=[], reasons=[], owasp={}, layer_results={}
)
FAKE_BLOCK = ScanResult(
    verdict="block",
    risk_score=95.0,
    categories=["prompt_injection"],
    reasons=["fake"],
    owasp={},
    layer_results={},
)


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL, future=True)
    connection = engine.connect()
    outer_txn = connection.begin()
    sess = Session(bind=connection, future=True)
    sess.begin_nested()

    yield sess

    sess.close()
    outer_txn.rollback()
    connection.close()
    engine.dispose()


@pytest.fixture()
def org(session):
    return db.create_org(session, "Acme Corp")


@pytest.fixture()
def raw_key():
    return f"sk-anzenna-{uuid.uuid4()}"


@pytest.fixture()
def api_key(session, org, raw_key):
    return db.create_api_key(session, org.id, raw_key, label="ci")


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    main._rate_windows.clear()
    yield
    main._rate_windows.clear()


@pytest.fixture()
def client(session, monkeypatch):
    def _get_session_override():
        yield session

    main.app.dependency_overrides[main.get_session] = _get_session_override
    monkeypatch.setattr(main, "engine_scan", lambda *a, **k: FAKE_ALLOW)
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def auth(raw_key):
    return {"Authorization": f"Bearer {raw_key}"}


def test_scan_requires_auth(client):
    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"})
    assert resp.status_code == 401


def test_scan_rejects_unknown_key(client):
    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth("sk-nope"))
    assert resp.status_code == 401


def test_scan_rejects_revoked_key(client, session, api_key, raw_key):
    db.revoke_api_key(session, api_key.id)
    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    assert resp.status_code == 401


def test_scan_missing_text_is_400(client, api_key, raw_key):
    resp = client.post("/v1/scan", json={"direction": "input"}, headers=auth(raw_key))
    assert resp.status_code == 400


def test_scan_invalid_direction_is_400(client, api_key, raw_key):
    resp = client.post("/v1/scan", json={"text": "hi", "direction": "sideways"}, headers=auth(raw_key))
    assert resp.status_code == 400


def test_scan_success_returns_contract_shape(client, api_key, raw_key):
    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "allow"
    assert body["risk_score"] == 0.0
    assert isinstance(body["latency_ms"], int)


def test_scan_logs_and_increments_usage(client, session, org, api_key, raw_key):
    assert db.get_usage(session, org.id, date.today().replace(day=1)) == 0

    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    assert resp.status_code == 200

    assert db.get_usage(session, org.id, date.today().replace(day=1)) == 1
    logs = db.list_scan_logs(session, org.id)
    assert len(logs) == 1
    assert logs[0].verdict == "allow"
    assert logs[0].api_key_id == api_key.id


def test_scan_usage_cap_exceeded_returns_429(client, session, org, api_key, raw_key):
    period_start = date.today().replace(day=1)
    db.increment_usage(session, org.id, period_start, by=main.PLAN_LIMITS["free"])

    resp = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    assert resp.status_code == 429
    body = resp.json()
    assert body["error"] == "usage_limit_exceeded"
    assert "reset_at" in body


def test_scan_rate_limit_exceeded_returns_429(client, api_key, raw_key, monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_PER_SECOND", 1)
    first = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    second = client.post("/v1/scan", json={"text": "hi", "direction": "input"}, headers=auth(raw_key))
    assert first.status_code == 200
    assert second.status_code == 429


def test_usage_endpoint_reflects_scan_count(client, session, org, api_key, raw_key):
    db.increment_usage(session, org.id, date.today().replace(day=1), by=3)
    resp = client.get("/v1/usage", headers=auth(raw_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["usage"] == 3
    assert body["limit"] == main.PLAN_LIMITS["free"]

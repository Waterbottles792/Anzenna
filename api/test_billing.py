"""Unit tests for api/billing.py -- the Dodo Payments SDK is fully mocked
(no network, no live Dodo account needed), against a real Postgres test DB
for the org rows Phase 8 reads/writes. Same skip/fixture pattern as
api/test_db.py.
"""

import os
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine

pytest.importorskip("sqlalchemy")

DATABASE_URL = os.environ.get("ANZENNA_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    pytest.skip(
        "set ANZENNA_TEST_DATABASE_URL (or DATABASE_URL) to a Postgres DB "
        "with DB_SCHEMA.sql applied to run api/test_billing.py -- see api/README.md",
        allow_module_level=True,
    )

from sqlalchemy.orm import Session  # noqa: E402

from api import billing, db  # noqa: E402


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


@pytest.fixture(autouse=True)
def _plan_product_ids(monkeypatch):
    monkeypatch.setattr(billing, "PLAN_PRODUCT_IDS", {"pro": "prod_pro_test", "scale": "prod_scale_test"})
    monkeypatch.setattr(billing, "_PRODUCT_ID_TO_PLAN", {"prod_pro_test": "pro", "prod_scale_test": "scale"})


def fake_client(*, customer_id="cus_test1", checkout_url="https://checkout.dodopayments.com/test"):
    fake = MagicMock()
    fake.customers.create.return_value = SimpleNamespace(customer_id=customer_id)
    fake.checkout_sessions.create.return_value = SimpleNamespace(checkout_url=checkout_url)
    return fake


def test_ensure_dodo_customer_creates_and_persists(session, org):
    client = fake_client(customer_id="cus_new1")
    customer_id = billing.ensure_dodo_customer(session, org.id, org_name=org.name, email="a@example.com", client=client)
    assert customer_id == "cus_new1"
    client.customers.create.assert_called_once_with(email="a@example.com", name=org.name)
    assert db.get_org(session, org.id).stripe_customer_id == "cus_new1"


def test_ensure_dodo_customer_idempotent_when_already_set(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_existing")
    client = fake_client()
    customer_id = billing.ensure_dodo_customer(session, org.id, org_name=org.name, email="a@example.com", client=client)
    assert customer_id == "cus_existing"
    client.customers.create.assert_not_called()


def test_create_checkout_session_returns_url(session, org):
    client = fake_client(checkout_url="https://checkout.dodopayments.com/session_123")
    url = billing.create_checkout_session(
        session,
        org.id,
        org_name=org.name,
        email="a@example.com",
        plan="pro",
        return_url="https://app.example/success",
        cancel_url="https://app.example/cancel",
        client=client,
    )
    assert url == "https://checkout.dodopayments.com/session_123"
    _, kwargs = client.checkout_sessions.create.call_args
    assert kwargs["product_cart"] == [{"product_id": "prod_pro_test", "quantity": 1}]
    assert kwargs["customer"] == {"customer_id": "cus_test1"}


def test_create_checkout_session_unknown_plan_raises(session, org):
    with pytest.raises(ValueError):
        billing.create_checkout_session(
            session,
            org.id,
            org_name=org.name,
            email="a@example.com",
            plan="ultra",
            return_url="https://app.example/success",
            cancel_url="https://app.example/cancel",
            client=fake_client(),
        )


def test_report_scan_usage_no_dodo_customer_is_noop(session, org):
    assert billing.report_scan_usage(session, org.id, uuid.uuid4(), client=fake_client()) is False


def test_report_scan_usage_ingests_event(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    client = fake_client()
    scan_id = uuid.uuid4()

    ok = billing.report_scan_usage(session, org.id, scan_id, client=client)

    assert ok is True
    client.usage_events.ingest.assert_called_once_with(
        events=[{"customer_id": "cus_test1", "event_id": str(scan_id), "event_name": "scan"}]
    )


def test_report_scan_usage_swallows_client_errors(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    client = fake_client()
    client.usage_events.ingest.side_effect = RuntimeError("network down")

    assert billing.report_scan_usage(session, org.id, uuid.uuid4(), client=client) is False


def test_handle_webhook_subscription_active_upgrades_plan(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    event = {
        "type": "subscription.active",
        "data": {"customer": {"customer_id": "cus_test1"}, "status": "active", "product_id": "prod_pro_test"},
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "pro"


def test_handle_webhook_subscription_renewed_to_scale(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "pro")
    event = {
        "type": "subscription.renewed",
        "data": {"customer": {"customer_id": "cus_test1"}, "status": "active", "product_id": "prod_scale_test"},
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "scale"


def test_handle_webhook_subscription_on_hold_downgrades_to_free(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "pro")
    event = {
        "type": "subscription.on_hold",
        "data": {"customer": {"customer_id": "cus_test1"}, "status": "on_hold", "product_id": "prod_pro_test"},
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"


def test_handle_webhook_subscription_cancelled_downgrades_to_free(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "scale")
    event = {
        "type": "subscription.cancelled",
        "data": {"customer": {"customer_id": "cus_test1"}, "status": "cancelled", "product_id": "prod_scale_test"},
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"


def test_handle_webhook_unknown_customer_is_noop(session):
    event = {
        "type": "subscription.cancelled",
        "data": {"customer": {"customer_id": "cus_does_not_exist"}, "status": "cancelled"},
    }
    billing.handle_webhook_event(session, event)  # should not raise


def test_handle_webhook_non_subscription_event_is_noop(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    event = {"type": "payment.failed", "data": {"customer": {"customer_id": "cus_test1"}}}
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"

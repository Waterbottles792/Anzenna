"""Unit tests for api/billing.py -- Stripe calls are fully mocked (no
network, no live Stripe account needed), against a real Postgres test DB for
the org rows Phase 8 reads/writes. Same skip/fixture pattern as
api/test_db.py.
"""

import os
from datetime import date
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
def _plan_price_ids(monkeypatch):
    monkeypatch.setattr(billing, "PLAN_PRICE_IDS", {"pro": "price_pro_test", "scale": "price_scale_test"})
    monkeypatch.setattr(billing, "_PRICE_ID_TO_PLAN", {"price_pro_test": "pro", "price_scale_test": "scale"})


def fake_stripe(*, customer_id="cus_test1", checkout_url="https://checkout.stripe.com/test", subscription_items=None):
    fake = MagicMock()
    fake.Customer.create.return_value = SimpleNamespace(id=customer_id)
    fake.checkout.Session.create.return_value = SimpleNamespace(url=checkout_url)
    fake.Subscription.list.return_value = SimpleNamespace(
        data=[{"items": {"data": subscription_items}}] if subscription_items is not None else []
    )
    return fake


def test_ensure_stripe_customer_creates_and_persists(session, org):
    stripe = fake_stripe(customer_id="cus_new1")
    customer_id = billing.ensure_stripe_customer(session, org.id, org_name=org.name, stripe_module=stripe)
    assert customer_id == "cus_new1"
    stripe.Customer.create.assert_called_once()
    assert db.get_org(session, org.id).stripe_customer_id == "cus_new1"


def test_ensure_stripe_customer_idempotent_when_already_set(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_existing")
    stripe = fake_stripe()
    customer_id = billing.ensure_stripe_customer(session, org.id, org_name=org.name, stripe_module=stripe)
    assert customer_id == "cus_existing"
    stripe.Customer.create.assert_not_called()


def test_create_checkout_session_returns_url(session, org):
    stripe = fake_stripe(checkout_url="https://checkout.stripe.com/session_123")
    url = billing.create_checkout_session(
        session,
        org.id,
        org_name=org.name,
        plan="pro",
        success_url="https://app.example/success",
        cancel_url="https://app.example/cancel",
        stripe_module=stripe,
    )
    assert url == "https://checkout.stripe.com/session_123"
    _, kwargs = stripe.checkout.Session.create.call_args
    assert kwargs["line_items"] == [{"price": "price_pro_test", "quantity": 1}]
    assert kwargs["mode"] == "subscription"


def test_create_checkout_session_unknown_plan_raises(session, org):
    with pytest.raises(ValueError):
        billing.create_checkout_session(
            session,
            org.id,
            org_name=org.name,
            plan="ultra",
            success_url="https://app.example/success",
            cancel_url="https://app.example/cancel",
            stripe_module=fake_stripe(),
        )


def test_report_usage_no_stripe_customer_is_noop(session, org):
    period = date.today().replace(day=1)
    assert billing.report_usage(session, org.id, period, stripe_module=fake_stripe()) is None


def test_report_usage_no_active_subscription_is_noop(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    period = date.today().replace(day=1)
    assert billing.report_usage(session, org.id, period, stripe_module=fake_stripe()) is None


def test_report_usage_creates_usage_record(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    period = date.today().replace(day=1)
    db.increment_usage(session, org.id, period, by=7)
    stripe = fake_stripe(subscription_items=[{"id": "si_123", "price": {"id": "price_pro_test"}}])

    quantity = billing.report_usage(session, org.id, period, stripe_module=stripe)

    assert quantity == 7
    stripe.SubscriptionItem.create_usage_record.assert_called_once_with("si_123", quantity=7, action="set")


def test_report_usage_for_all_orgs_skips_orgs_without_stripe_customer(session, org):
    other = db.create_org(session, "Other Org")
    db.set_org_stripe_customer_id(session, other.id, "cus_other")
    period = date.today().replace(day=1)
    db.increment_usage(session, other.id, period, by=4)
    stripe = fake_stripe(subscription_items=[{"id": "si_999", "price": {"id": "price_pro_test"}}])

    reported = billing.report_usage_for_all_orgs(session, period, stripe_module=stripe)

    assert org.id not in reported
    assert reported[other.id] == 4


def test_handle_webhook_subscription_created_upgrades_plan(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    event = {
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "customer": "cus_test1",
                "status": "active",
                "items": {"data": [{"price": {"id": "price_pro_test"}}]},
            }
        },
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "pro"


def test_handle_webhook_subscription_updated_to_scale(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "pro")
    event = {
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "customer": "cus_test1",
                "status": "active",
                "items": {"data": [{"price": {"id": "price_scale_test"}}]},
            }
        },
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "scale"


def test_handle_webhook_subscription_past_due_downgrades_to_free(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "pro")
    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {"customer": "cus_test1", "status": "past_due", "items": {"data": []}}},
    }
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"


def test_handle_webhook_subscription_deleted_downgrades_to_free(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    db.set_org_plan(session, org.id, "scale")
    event = {"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_test1"}}}
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"


def test_handle_webhook_unknown_customer_is_noop(session):
    event = {"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_does_not_exist"}}}
    billing.handle_webhook_event(session, event)  # should not raise


def test_handle_webhook_unhandled_event_type_is_noop(session, org):
    db.set_org_stripe_customer_id(session, org.id, "cus_test1")
    event = {"type": "invoice.payment_failed", "data": {"object": {"customer": "cus_test1"}}}
    billing.handle_webhook_event(session, event)
    assert db.get_org(session, org.id).plan == "free"

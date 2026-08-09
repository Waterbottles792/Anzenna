"""Phase 8 -- Dodo Payments billing (Merchant of Record).

Swapped from Stripe: Stripe went invite-only for India-based businesses in
May 2024, so a Stripe account isn't obtainable here. Dodo Payments is a
Merchant of Record aimed at India-based SaaS founders selling globally --
it also handles VAT/GST/sales-tax compliance itself, unlike Stripe.

No live Dodo Payments account is available in this dev environment, so
every call into the SDK goes through an injectable `client` parameter
(default: the real `dodopayments.DodoPayments`, lazily constructed) -- same
pattern engine/llm_judge.py uses for its judge_fn. That makes this module
fully unit-testable against a fake client with zero network calls.

Product ids come from env (DODO_PRODUCT_ID_PRO/DODO_PRODUCT_ID_SCALE, see
.env.example) rather than being created here -- creating the actual Dodo
products is a one-time dashboard action (see api/README.md), not something
this module should do at import time.
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from api import db

PLAN_PRODUCT_IDS = {
    "pro": os.environ.get("DODO_PRODUCT_ID_PRO", ""),
    "scale": os.environ.get("DODO_PRODUCT_ID_SCALE", ""),
}
_PRODUCT_ID_TO_PLAN = {v: k for k, v in PLAN_PRODUCT_IDS.items() if v}


def dodo_client():
    """Real client factory -- also used by api/main.py's webhook route
    (needs `.webhooks.unwrap()`), not just the functions in this module."""
    from dodopayments import DodoPayments  # heavy/optional (Phase 8's `billing` extra) -- lazy import

    return DodoPayments(
        bearer_token=os.environ.get("DODO_PAYMENTS_API_KEY"),
        webhook_key=os.environ.get("DODO_PAYMENTS_WEBHOOK_KEY"),
        environment=os.environ.get("DODO_PAYMENTS_ENVIRONMENT", "live_mode"),
    )


def ensure_dodo_customer(session: Session, org_id: uuid.UUID, *, org_name: str, email: str, client=None) -> str:
    """Create+persist a Dodo Payments customer for `org_id` if it doesn't
    have one yet. Idempotent: returns the existing id with no API call if
    already set.

    Persisted into orgs.stripe_customer_id -- that column name is frozen
    (DB_SCHEMA.sql is a contract that "never changes after Phase 0" per
    docs/plan.md), and adding a near-duplicate column just to rename one
    string field would be pure churn.
    """
    org = db.get_org(session, org_id)
    assert org is not None
    if org.stripe_customer_id:
        return org.stripe_customer_id
    client = client or dodo_client()
    customer = client.customers.create(email=email, name=org_name)
    db.set_org_stripe_customer_id(session, org_id, customer.customer_id)
    return customer.customer_id


def create_checkout_session(
    session: Session,
    org_id: uuid.UUID,
    *,
    org_name: str,
    email: str,
    plan: str,
    return_url: str,
    cancel_url: str,
    client=None,
) -> str:
    """Create a Dodo Payments checkout session upgrading `org_id` to `plan`
    (pro|scale) and return its hosted checkout URL."""
    if plan not in PLAN_PRODUCT_IDS or not PLAN_PRODUCT_IDS[plan]:
        raise ValueError(f"unknown or unconfigured plan: {plan!r}")
    client = client or dodo_client()
    customer_id = ensure_dodo_customer(session, org_id, org_name=org_name, email=email, client=client)
    checkout = client.checkout_sessions.create(
        customer={"customer_id": customer_id},
        product_cart=[{"product_id": PLAN_PRODUCT_IDS[plan], "quantity": 1}],
        return_url=return_url,
        cancel_url=cancel_url,
        metadata={"org_id": str(org_id), "plan": plan},
    )
    return checkout.checkout_url


def report_scan_usage(session: Session, org_id: uuid.UUID, scan_log_id: uuid.UUID, *, client=None) -> bool:
    """Report one scan as a usage event for metered pro/scale billing.
    Called by api/main.py right after logging a scan.

    Dodo's usage-events API ingests one event per unit of usage (deduped by
    `event_id`), unlike Stripe's usage records which `set` a period's
    cumulative total -- so this fires per scan rather than the daily-batch
    design a Stripe-shaped API would use. No-ops (returns False) for orgs
    with no Dodo customer (free plan) -- checked before touching the
    client, so free-plan scans never need Dodo credentials configured.
    Never raises: a billing hiccup must never fail the customer's actual
    scan response.
    """
    org = db.get_org(session, org_id)
    if org is None or not org.stripe_customer_id:
        return False
    client = client or dodo_client()
    try:
        client.usage_events.ingest(
            events=[
                {
                    "customer_id": org.stripe_customer_id,
                    "event_id": str(scan_log_id),
                    "event_name": "scan",
                }
            ]
        )
    except Exception:
        return False
    return True


def _plan_for_subscription(subscription: dict) -> Optional[str]:
    return _PRODUCT_ID_TO_PLAN.get(subscription.get("product_id"))


def handle_webhook_event(session: Session, event: dict) -> None:
    """Apply one Dodo Payments webhook event (already signature-verified by
    the caller -- see api/main.py's POST /webhooks/dodo-payments) to
    orgs.plan. `event` is the SDK's parsed event dict (`.model_dump()`'d):
    `{"type": "subscription.<x>", "data": {...Subscription fields...}, ...}`.

    Every subscription.* event type (active/renewed/updated/plan_changed/
    cancelled/expired/failed/on_hold) carries the subscription's current
    `status` in `data` -- so status, not event type, decides the plan:
    "active" -> plan derived from the subscription's product id; anything
    else -> downgrade to free. Non-subscription events (payment.*,
    refund.*, ...) are accepted and ignored -- DB_SCHEMA.sql's orgs table
    has no status column to record them in (frozen contract).
    """
    event_type = event.get("type", "")
    if not event_type.startswith("subscription."):
        return
    subscription = event.get("data", {})
    customer_id = (subscription.get("customer") or {}).get("customer_id")
    if not customer_id:
        return
    org = db.get_org_by_stripe_customer_id(session, customer_id)
    if org is None:
        return

    if subscription.get("status") == "active":
        plan = _plan_for_subscription(subscription)
        if plan is not None:
            db.set_org_plan(session, org.id, plan)
    else:
        db.set_org_plan(session, org.id, "free")

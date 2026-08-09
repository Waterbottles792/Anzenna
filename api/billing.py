"""Phase 8 -- Stripe billing.

Metered pro/scale tiers on top of Phase 6/7's orgs.plan and usage_counters.
No live Stripe account is available in this dev environment, so every call
into the SDK goes through an injectable `stripe_module` parameter (default:
the real `stripe` package, lazily imported) -- the same pattern
engine/llm_judge.py uses for its judge_fn. That makes this module fully
unit-testable against fake responses with zero network calls, and the real
SDK is swapped in unmodified in production.

Price IDs come from env (STRIPE_PRICE_ID_PRO/STRIPE_PRICE_ID_SCALE, see
.env.example) rather than being created here -- creating the actual Stripe
products/prices is a one-time dashboard/CLI action (see api/README.md), not
something this module should do at import time.
"""

from __future__ import annotations

import os
import uuid
from datetime import date
from typing import Optional

from sqlalchemy.orm import Session

from api import db

PLAN_PRICE_IDS = {
    "pro": os.environ.get("STRIPE_PRICE_ID_PRO", ""),
    "scale": os.environ.get("STRIPE_PRICE_ID_SCALE", ""),
}
_PRICE_ID_TO_PLAN = {v: k for k, v in PLAN_PRICE_IDS.items() if v}

# Subscription statuses that count as "paying" -- a trialing subscription
# already has a plan+price attached even before the first invoice.
_ACTIVE_STATUSES = {"active", "trialing"}


def _stripe_module():
    import stripe  # heavy/optional (Phase 8's `billing` extra) -- lazy import

    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    return stripe


def ensure_stripe_customer(session: Session, org_id: uuid.UUID, *, org_name: str, stripe_module=None) -> str:
    """Create+persist a Stripe customer for `org_id` if it doesn't have one
    yet. Idempotent: returns the existing id with no API call if already set."""
    org = db.get_org(session, org_id)
    assert org is not None
    if org.stripe_customer_id:
        return org.stripe_customer_id
    stripe_module = stripe_module or _stripe_module()
    customer = stripe_module.Customer.create(name=org_name, metadata={"org_id": str(org_id)})
    db.set_org_stripe_customer_id(session, org_id, customer.id)
    return customer.id


def create_checkout_session(
    session: Session,
    org_id: uuid.UUID,
    *,
    org_name: str,
    plan: str,
    success_url: str,
    cancel_url: str,
    stripe_module=None,
) -> str:
    """Create a Stripe Checkout session upgrading `org_id` to `plan`
    (pro|scale) and return its hosted checkout URL."""
    if plan not in PLAN_PRICE_IDS or not PLAN_PRICE_IDS[plan]:
        raise ValueError(f"unknown or unconfigured plan: {plan!r}")
    stripe_module = stripe_module or _stripe_module()
    customer_id = ensure_stripe_customer(session, org_id, org_name=org_name, stripe_module=stripe_module)
    checkout_session = stripe_module.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": PLAN_PRICE_IDS[plan], "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"org_id": str(org_id), "plan": plan},
    )
    return checkout_session.url


def _find_metered_subscription_item(stripe_module, customer_id: str) -> Optional[str]:
    subs = stripe_module.Subscription.list(customer=customer_id, status="active", limit=1)
    if not subs.data:
        return None
    for item in subs.data[0]["items"]["data"]:
        if item["price"]["id"] in _PRICE_ID_TO_PLAN:
            return item["id"]
    return None


def report_usage(session: Session, org_id: uuid.UUID, period_start: date, *, stripe_module=None) -> Optional[int]:
    """Report this period's scan_count to Stripe as a metered usage record
    against the org's active subscription item (plan.md Phase 8 task 2).
    Returns None (no-op) for orgs with no Stripe customer or no active
    metered subscription item -- free-plan orgs have neither."""
    org = db.get_org(session, org_id)
    if org is None or not org.stripe_customer_id:
        return None
    stripe_module = stripe_module or _stripe_module()
    item_id = _find_metered_subscription_item(stripe_module, org.stripe_customer_id)
    if item_id is None:
        return None
    quantity = db.get_usage(session, org_id, period_start)
    stripe_module.SubscriptionItem.create_usage_record(item_id, quantity=quantity, action="set")
    return quantity


def report_usage_for_all_orgs(session: Session, period_start: date, *, stripe_module=None) -> dict[uuid.UUID, int]:
    """The "daily batch job reading usage_counters" plan.md Phase 8 task 2
    describes. Intentionally just a function to call from a scheduler (cron,
    a platform's scheduled-task feature, ...) -- provisioning that scheduler
    is an infra/deploy concern (plan.md Phase 12), not billing logic."""
    stripe_module = stripe_module or _stripe_module()
    reported = {}
    for org in db.list_orgs_with_stripe_customer(session):
        quantity = report_usage(session, org.id, period_start, stripe_module=stripe_module)
        if quantity is not None:
            reported[org.id] = quantity
    return reported


def _plan_for_subscription(subscription_obj) -> Optional[str]:
    for item in subscription_obj.get("items", {}).get("data", []):
        price_id = item.get("price", {}).get("id")
        if price_id in _PRICE_ID_TO_PLAN:
            return _PRICE_ID_TO_PLAN[price_id]
    return None


def handle_webhook_event(session: Session, event) -> None:
    """Apply one Stripe webhook event (already signature-verified by the
    caller -- see api/main.py's POST /webhooks/stripe) to orgs.plan.

    subscription created/updated -> plan derived from the subscription's
    price id, applied while active/trialing; downgraded to free otherwise
    (e.g. past_due, unpaid).
    subscription deleted (canceled) -> downgrade to free.
    Other event types (invoice.payment_failed, etc.) are accepted and
    ignored -- DB_SCHEMA.sql's orgs table has no status column to record
    them in (it's a frozen contract per docs/plan.md); Stripe's own
    dashboard/dunning emails are the source of truth for those until a
    status column exists.
    """
    event_type = event.get("type", "")
    obj = event.get("data", {}).get("object", {})
    customer_id = obj.get("customer")
    if not customer_id:
        return
    org = db.get_org_by_stripe_customer_id(session, customer_id)
    if org is None:
        return

    if event_type in ("customer.subscription.created", "customer.subscription.updated"):
        if obj.get("status") in _ACTIVE_STATUSES:
            plan = _plan_for_subscription(obj)
            if plan is not None:
                db.set_org_plan(session, org.id, plan)
        else:
            db.set_org_plan(session, org.id, "free")
    elif event_type == "customer.subscription.deleted":
        db.set_org_plan(session, org.id, "free")

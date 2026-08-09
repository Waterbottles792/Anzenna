"""Phase 7 -- FastAPI service: auth, POST /v1/scan, GET /v1/usage, rate limiting.

Wires engine.scan() (Phase 5, zero web/DB deps) to api/db.py's CRUD helpers
(Phase 6) per docs/contracts/API_CONTRACT.md. The contract's dashboard-
internal endpoints (/v1/keys, /v1/logs) are session-auth, tied to Phase 9's
auth provider (not built yet) -- left for that phase, not this one.

Body validation is manual, not a pydantic request model: the contract
requires 400 for a malformed request, and FastAPI's automatic model
validation always yields 422, so a hand-rolled check is the more direct fit
here rather than fighting the framework's default.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api import billing, db
from engine.pipeline import scan as engine_scan

app = FastAPI(title="Anzenna API")

# Monthly scan_count caps per docs/plan.md Phase 7 task 4. No plan_limits
# table exists in DB_SCHEMA.sql (orgs.plan is just free|pro|scale), so these
# are a code-level constant -- move to a table if plans ever need per-org
# overrides.
PLAN_LIMITS = {"free": 1_000, "pro": 50_000, "scale": 1_000_000}

# ponytail: in-memory fixed-window counter, one process only -- fine for a
# single-instance deploy. Swap for a Redis-backed limiter (plan.md Phase 7
# task 6 already flags this as the scale-up path) if this ever runs behind
# multiple workers/instances.
RATE_LIMIT_PER_SECOND = int(os.environ.get("ANZENNA_RATE_LIMIT_PER_SECOND", "10"))
_rate_windows: dict[str, tuple[int, int]] = {}


def _rate_limit_ok(key: str) -> bool:
    now = int(time.time())
    window_start, count = _rate_windows.get(key, (now, 0))
    if window_start != now:
        window_start, count = now, 0
    count += 1
    _rate_windows[key] = (window_start, count)
    return count <= RATE_LIMIT_PER_SECOND


def _period_start(today: Optional[date] = None) -> date:
    return (today or datetime.now(timezone.utc).date()).replace(day=1)


def _next_period_start(period_start: date) -> date:
    if period_start.month == 12:
        return period_start.replace(year=period_start.year + 1, month=1)
    return period_start.replace(month=period_start.month + 1)


_session_factory = None


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = db.make_session_factory(os.environ["DATABASE_URL"])
    return _session_factory


def get_session():
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class AuthedKey(BaseModel):
    org_id: uuid.UUID
    api_key_id: uuid.UUID
    plan: str


_bearer = HTTPBearer(auto_error=False)


def require_api_key(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    session: Session = Depends(get_session),
) -> AuthedKey:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="missing API key")
    key = db.get_api_key_by_raw_key(session, creds.credentials)
    if key is None or key.revoked_at is not None:
        raise HTTPException(status_code=401, detail="invalid or revoked API key")
    if not _rate_limit_ok(str(key.id)):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    org = db.get_org(session, key.org_id)
    assert org is not None  # FK guarantees a matching org row
    return AuthedKey(org_id=key.org_id, api_key_id=key.id, plan=org.plan)


@app.post("/v1/scan")
async def post_scan(
    request: Request,
    session: Session = Depends(get_session),
    auth: AuthedKey = Depends(require_api_key),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="malformed JSON body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="malformed JSON body")

    text = body.get("text")
    direction = body.get("direction")
    context = body.get("context")
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=400, detail="'text' is required")
    if direction not in ("input", "output"):
        raise HTTPException(status_code=400, detail="'direction' must be 'input' or 'output'")
    if context is not None and not isinstance(context, dict):
        raise HTTPException(status_code=400, detail="'context' must be an object")

    period_start = _period_start()
    limit = PLAN_LIMITS.get(auth.plan, PLAN_LIMITS["free"])
    if db.get_usage(session, auth.org_id, period_start) >= limit:
        reset_at = _next_period_start(period_start)
        return JSONResponse(
            status_code=429,
            content={"error": "usage_limit_exceeded", "reset_at": f"{reset_at.isoformat()}T00:00:00Z"},
        )

    started = time.perf_counter()
    try:
        result = engine_scan(text, direction=direction, context=context)
    except Exception:
        raise HTTPException(status_code=500, detail="scan failed")
    latency_ms = int((time.perf_counter() - started) * 1000)

    scan_log = db.log_scan(
        session,
        org_id=auth.org_id,
        api_key_id=auth.api_key_id,
        direction=direction,
        verdict=result.verdict,
        risk_score=int(result.risk_score),
        categories=result.categories,
        latency_ms=latency_ms,
        text_preview=text,
    )
    db.increment_usage(session, auth.org_id, period_start)
    billing.report_scan_usage(session, auth.org_id, scan_log.id)  # no-op for free-plan orgs; never raises

    return {**result.to_dict(), "latency_ms": latency_ms}


@app.get("/v1/usage")
def get_usage(
    session: Session = Depends(get_session),
    auth: AuthedKey = Depends(require_api_key),
):
    period_start = _period_start()
    limit = PLAN_LIMITS.get(auth.plan, PLAN_LIMITS["free"])
    return {
        "usage": db.get_usage(session, auth.org_id, period_start),
        "limit": limit,
        "period_start": period_start.isoformat(),
    }


@app.post("/v1/billing/checkout")
async def post_billing_checkout(
    request: Request,
    session: Session = Depends(get_session),
    auth: AuthedKey = Depends(require_api_key),
):
    """Not part of docs/contracts/API_CONTRACT.md (frozen since Phase 0) --
    a Phase 8 addition, same as engine/owasp.py's tags were a Phase-5+
    addition beyond the original engine contract. Reuses API-key auth since
    no session-auth dashboard exists yet (Phase 9); switch this to session
    auth once it does, since a checkout link is normally a logged-in-user
    action, not a server-to-server one."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="malformed JSON body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="malformed JSON body")

    plan = body.get("plan")
    email = body.get("email")
    return_url = body.get("return_url")
    cancel_url = body.get("cancel_url")
    if plan not in ("pro", "scale"):
        raise HTTPException(status_code=400, detail="'plan' must be 'pro' or 'scale'")
    if not isinstance(email, str) or not email:
        raise HTTPException(status_code=400, detail="'email' is required")
    if not isinstance(return_url, str) or not isinstance(cancel_url, str) or not return_url or not cancel_url:
        raise HTTPException(status_code=400, detail="'return_url' and 'cancel_url' are required")

    org = db.get_org(session, auth.org_id)
    assert org is not None  # FK guarantees this
    try:
        checkout_url = billing.create_checkout_session(
            session,
            auth.org_id,
            org_name=org.name,
            email=email,
            plan=plan,
            return_url=return_url,
            cancel_url=cancel_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"checkout_url": checkout_url}


@app.post("/webhooks/dodo-payments")
async def dodo_payments_webhook(request: Request, session: Session = Depends(get_session)):
    payload = await request.body()
    try:
        client = billing.dodo_client()
        event = client.webhooks.unwrap(
            payload.decode("utf-8"),
            headers={
                "webhook-id": request.headers.get("webhook-id", ""),
                "webhook-signature": request.headers.get("webhook-signature", ""),
                "webhook-timestamp": request.headers.get("webhook-timestamp", ""),
            },
        )
    except Exception:
        raise HTTPException(status_code=400, detail="invalid webhook signature")

    billing.handle_webhook_event(session, event.model_dump())
    return {"received": True}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "internal_error"})

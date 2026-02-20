"""
OR1ON Billing Service v6.0
Stripe-based subscription management with webhook handling.
"""

import os
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel, EmailStr
import stripe

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("or1on-billing")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

if not stripe.api_key:
    logger.warning("STRIPE_SECRET_KEY not set — billing service will fail on Stripe calls")

app = FastAPI(title="OR1ON Billing Service", version="6.0.0")

PLANS = {
    "starter": {"name": "Starter", "features": ["api_access", "1_tenant"], "price_id": os.environ.get("STRIPE_PRICE_STARTER", "")},
    "professional": {"name": "Professional", "features": ["api_access", "5_tenants", "audit_trail", "priority_support"], "price_id": os.environ.get("STRIPE_PRICE_PRO", "")},
    "enterprise": {"name": "Enterprise", "features": ["api_access", "unlimited_tenants", "audit_trail", "sla_99_9", "dedicated_support", "custom_integrations"], "price_id": os.environ.get("STRIPE_PRICE_ENTERPRISE", "")},
}


class CreateCustomerRequest(BaseModel):
    email: str
    name: str
    tenant_id: str


class SubscribeRequest(BaseModel):
    customer_id: str
    plan: str


@app.get("/health")
async def health():
    return {"status": "healthy", "stripe_configured": bool(stripe.api_key)}


@app.get("/plans")
async def list_plans():
    """List available subscription plans."""
    return {"plans": PLANS}


@app.post("/customers")
async def create_customer(req: CreateCustomerRequest):
    """Create a Stripe customer linked to a tenant."""
    try:
        customer = stripe.Customer.create(
            email=req.email,
            name=req.name,
            metadata={"tenant_id": req.tenant_id, "platform": "or1on"},
        )
        logger.info(f"Customer created: {customer.id} for tenant {req.tenant_id}")
        return {"customer_id": customer.id, "email": req.email}
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/subscriptions")
async def create_subscription(req: SubscribeRequest):
    """Create a subscription for a customer."""
    if req.plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {req.plan}. Available: {list(PLANS.keys())}")

    price_id = PLANS[req.plan]["price_id"]
    if not price_id:
        raise HTTPException(status_code=500, detail=f"Price ID not configured for plan: {req.plan}")

    try:
        subscription = stripe.Subscription.create(
            customer=req.customer_id,
            items=[{"price": price_id}],
            metadata={"plan": req.plan, "platform": "or1on"},
        )
        logger.info(f"Subscription created: {subscription.id} for customer {req.customer_id}")
        return {"subscription_id": subscription.id, "status": subscription.status, "plan": req.plan}
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/subscriptions/{customer_id}")
async def get_subscription(customer_id: str):
    """Get active subscriptions for a customer."""
    try:
        subscriptions = stripe.Subscription.list(customer=customer_id, status="active")
        return {"customer_id": customer_id, "subscriptions": [{"id": s.id, "status": s.status, "plan": s.metadata.get("plan", "unknown")} for s in subscriptions.auto_paging_iter()]}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhook events."""
    payload = await request.body()

    if STRIPE_WEBHOOK_SECRET and stripe_signature:
        try:
            event = stripe.Webhook.construct_event(payload, stripe_signature, STRIPE_WEBHOOK_SECRET)
        except (ValueError, stripe.error.SignatureVerificationError) as e:
            logger.error(f"Webhook signature verification failed: {e}")
            raise HTTPException(status_code=400, detail="Invalid signature")
    else:
        event = json.loads(payload)

    event_type = event.get("type", "")
    logger.info(f"Webhook received: {event_type}")

    if event_type == "customer.subscription.created":
        logger.info("New subscription created")
    elif event_type == "customer.subscription.deleted":
        logger.info("Subscription cancelled")
    elif event_type == "invoice.payment_failed":
        logger.warning("Payment failed — action required")
    elif event_type == "invoice.payment_succeeded":
        logger.info("Payment succeeded")

    return {"received": True}
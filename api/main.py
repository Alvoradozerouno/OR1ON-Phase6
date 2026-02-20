"""
OR1ON SaaS API v6.0
Multi-tenant FastAPI service with Keycloak OIDC authentication.
"""

import os
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("or1on-api")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "https://auth.or1on.cloud")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "or1on")

oauth = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("OR1ON API v6.0 starting")
    yield
    logger.info("OR1ON API shutting down")

app = FastAPI(
    title="OR1ON SaaS API",
    version="6.0.0",
    description="Enterprise multi-tenant SaaS platform API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"https://app.{os.environ.get('DOMAIN', 'or1on.cloud')}"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def verify_token(token: str = Depends(oauth)) -> dict:
    """Verify JWT token against Keycloak userinfo endpoint."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return resp.json()


@app.get("/health")
async def health():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "healthy", "version": "6.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/ready")
async def ready():
    """Readiness check endpoint."""
    return {"status": "ready"}


@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "service": "OR1ON SaaS API",
        "version": "6.0.0",
        "status": "online",
        "docs": "/docs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/tenant/profile")
async def tenant_profile(user: dict = Depends(verify_token)):
    """Get current tenant profile."""
    return {
        "user": user.get("preferred_username", "unknown"),
        "email": user.get("email", ""),
        "tenant_id": user.get("tenant_id", "default"),
        "roles": user.get("realm_access", {}).get("roles", []),
    }


@app.get("/api/v1/tenant/data")
async def tenant_data(user: dict = Depends(verify_token)):
    """Get tenant-specific data."""
    return {
        "tenant_id": user.get("tenant_id", "default"),
        "data": {
            "resources": 0,
            "api_calls_today": 0,
            "storage_used_mb": 0,
        },
    }


@app.get("/api/v1/billing/status")
async def billing_status(user: dict = Depends(verify_token)):
    """Get billing status for authenticated tenant."""
    return {
        "tenant_id": user.get("tenant_id", "default"),
        "plan": "professional",
        "status": "active",
        "features": ["api_access", "multi_tenant", "audit_trail", "support_priority"],
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
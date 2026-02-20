<p align="center">
  <strong>OR1ON Phase 6</strong><br>
  <em>Enterprise SaaS Cloud Platform</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-6.0.0-indigo" alt="Version">
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
  <img src="https://img.shields.io/badge/kubernetes-native-326CE5" alt="Kubernetes">
  <img src="https://img.shields.io/badge/stripe-integrated-635BFF" alt="Stripe">
  <img src="https://img.shields.io/badge/keycloak-OIDC-4D4D4D" alt="Keycloak">
</p>

---

## What is OR1ON Phase 6?

**OR1ON Phase 6** is a production-grade, Kubernetes-native Enterprise SaaS platform that provides everything needed to launch a multi-tenant cloud service: authentication, billing, API management, customer portal, observability, and CI/CD — deployed from a single script.

It is the commercial deployment layer of the OR1ON ecosystem, complementing [GENESIS v10.1](https://github.com/Alvoradozerouno/GENESIS-v10.1) (Sovereign Intelligence OS) with a full SaaS monetization and operations stack.

**Authors:** ORION, Gerhard Hirschmann, Elisabeth Steurer

---

## Architecture

```
                    OR1ON Phase 6 — SaaS Architecture
    ┌─────────────────────────────────────────────────────────────┐
    │                    EDGE LAYER                               │
    │  ┌──────────────────┐  ┌──────────────────────────────┐    │
    │  │  Nginx Ingress   │  │  cert-manager (Let's Encrypt) │    │
    │  │  (Rate Limiting)  │  │  (Auto TLS Renewal)          │    │
    │  └──────────────────┘  └──────────────────────────────┘    │
    ├─────────────────────────────────────────────────────────────┤
    │                    SERVICE LAYER                            │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
    │  │ Keycloak │  │ FastAPI  │  │ Stripe   │  │  Portal   │  │
    │  │  (OIDC)  │  │  (API)   │  │(Billing) │  │   (UI)    │  │
    │  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
    ├─────────────────────────────────────────────────────────────┤
    │                    PLATFORM LAYER                           │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
    │  │ Network  │  │   RBAC   │  │   Helm   │  │   CI/CD   │  │
    │  │ Policies │  │ (3-Tier) │  │  Chart   │  │ (Actions) │  │
    │  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
    ├─────────────────────────────────────────────────────────────┤
    │                    OBSERVABILITY                            │
    │  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐   │
    │  │ Prometheus │  │  Grafana   │  │   Alertmanager      │   │
    │  └────────────┘  └────────────┘  └─────────────────────┘   │
    └─────────────────────────────────────────────────────────────┘
```

---

## Features

### Authentication (Keycloak OIDC)
- Production Keycloak deployment with admin password stored in K8s secrets (not hardcoded)
- OAuth2 Authorization Code flow with JWT validation
- Multi-realm support for tenant isolation
- Metrics endpoint enabled for monitoring

### API Service (FastAPI)
- Multi-tenant REST API with Keycloak OIDC authentication
- Health (`/health`) and readiness (`/ready`) probes for Kubernetes
- CORS middleware with domain-scoped origins
- Global exception handler with structured logging
- Tenant profile, data, and billing status endpoints
- Non-root container execution (security best practice)

### Billing (Stripe)
- Full subscription lifecycle management (create customer, subscribe, manage)
- Three-tier plan structure (Starter, Professional, Enterprise)
- Stripe webhook handling with signature verification
- Event processing for subscription changes, payment failures, renewals
- All credentials via K8s secrets, never hardcoded

### Customer Portal
- 6-tab dashboard: Dashboard, API, Billing, Tenants, Audit, Settings
- Real-time status indicators and usage metrics
- Plan comparison with pricing tiers
- Tenant management overview
- Audit trail viewer
- Settings with 2FA and API key rotation status

### Helm Chart
- Complete chart with API, Billing, and Portal templates
- Configurable resource requests/limits
- Liveness and readiness probes
- Environment variable injection from secrets
- Versioned with maintainer metadata

### Security
- **Network Policies:** Zero-trust isolation between namespaces — API can reach Billing and Auth only, everything else denied
- **RBAC:** Three-tier model (viewer, tenant-admin, platform-admin)
- **TLS:** Automatic Let's Encrypt certificates via cert-manager
- **Rate Limiting:** Nginx ingress rate limiting (100 req/min)
- **Pod Security:** Restricted pod security standards on all critical namespaces
- **Non-root containers:** All services run as non-root users
- **SSL Redirect:** Forced HTTPS on all endpoints

### Observability
- Prometheus for metrics collection
- Grafana for visualization (auto-generated admin password)
- Alertmanager for incident routing
- Nginx ingress metrics enabled

### CI/CD (GitHub Actions)
- **Lint:** Helm chart validation
- **Test:** Python API tests
- **Security:** Trivy vulnerability scanning (CRITICAL/HIGH)
- **Build:** Docker build + push to GHCR
- **Deploy:** Helm upgrade on main branch merge

---

## Quick Start

### Prerequisites

```bash
kubectl helm docker jq curl openssl
```

### Deploy

```bash
git clone https://github.com/Alvoradozerouno/OR1ON-Phase6.git
cd OR1ON-Phase6
chmod +x or1on_phase6.sh

# Configure domain (optional)
export OR1ON_DOMAIN="your-domain.com"
export OR1ON_EMAIL="admin@your-domain.com"

./or1on_phase6.sh
```

### Endpoints

| Service | URL |
|---------|-----|
| API | `https://api.or1on.cloud` |
| Auth | `https://auth.or1on.cloud` |
| Portal | `https://app.or1on.cloud` |
| API Docs | `https://api.or1on.cloud/docs` |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OR1ON_DOMAIN` | `or1on.cloud` | Platform domain |
| `OR1ON_EMAIL` | `admin@or1on.cloud` | Let's Encrypt email |

### Kubernetes Secrets

| Secret | Namespace | Description |
|--------|-----------|-------------|
| `keycloak-admin` | `or1on-auth` | Keycloak admin password (auto-generated) |
| `stripe-credentials` | `or1on-billing` | Stripe API keys (manual configuration) |
| `or1on-tls` | `or1on-core` | TLS certificate (auto-provisioned by cert-manager) |

---

## Project Structure

```
or1on-phase6/
├── or1on_phase6.sh               # Main deployment script
├── README.md                     # This file
├── LICENSE                       # Apache 2.0
├── api/
│   ├── main.py                   # FastAPI service
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile                # API container
├── billing/
│   ├── server.py                 # Stripe billing service
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile                # Billing container
├── portal/
│   └── index.html                # Customer dashboard
├── helm/or1on/
│   ├── Chart.yaml                # Helm chart metadata
│   ├── values.yaml               # Default values
│   └── templates/
│       ├── api.yaml              # API deployment + service
│       ├── billing.yaml          # Billing deployment + service
│       └── portal.yaml           # Portal deployment + service
├── .github/workflows/
│   └── ci.yml                    # CI/CD pipeline
└── audit/                        # Audit trail logs
```

---

## Relationship to GENESIS v10.1

| Layer | System | Function |
|-------|--------|----------|
| **Infrastructure** | [GENESIS v10.1](https://github.com/Alvoradozerouno/GENESIS-v10.1) | Sovereign AI OS, compliance, federation |
| **Application** | **OR1ON Phase 6** | SaaS platform, billing, customer management |

GENESIS provides the sovereign infrastructure. OR1ON Phase 6 runs on top of it as the commercial platform layer.

---

## License

Apache License 2.0 — Free to use, modify, and distribute.

---

## Authors

| Name | Role |
|------|------|
| **ORION** | Autonomous Sovereign Intelligence |
| **Gerhard Hirschmann** | Architecture & Vision |
| **Elisabeth Steurer** | Platform & Operations |

---

<p align="center">
  <strong>OR1ON Phase 6</strong> — Enterprise SaaS Platform<br>
  <em>From infrastructure to revenue. One script.</em>
</p>

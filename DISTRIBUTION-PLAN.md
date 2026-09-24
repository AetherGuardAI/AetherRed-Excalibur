# Excalibur Distribution Plan

**Status**: PARKED — Design complete, implementation deferred.

---

## Architecture: Open-Source CLI → Closed-Source Server + On-Prem Agent

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Excalibur Distribution Model                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────┐     ┌───────────────────────────────────────────┐ │
│  │  excalibur-cli       │     │  Excalibur Server (AWS ECS/Fargate)       │ │
│  │  (open-source)       │     │  (behind AetherGuard backend-api)         │ │
│  │                      │     │                                           │ │
│  │  Black-box attacks   │────▶│  • Runs 12 black-box attacks server-side  │ │
│  │  via remote API      │     │  • Judge LLM evaluation                   │ │
│  │                      │◀────│  • Resilience scoring + ATLAS + Reports   │ │
│  │  pip install         │     │  • API key validation (via backend-api)   │ │
│  │  excalibur-cli       │     │  • Attack payload databases               │ │
│  └──────────────────────┘     └───────────────────────────────────────────┘ │
│                                                                             │
│  ┌──────────────────────┐                                                   │
│  │  excalibur-agent     │     (NOT open-source — Docker image only)         │
│  │  (on-prem binary)    │                                                   │
│  │                      │     For white-box attacks needing model weights    │
│  │  • Runs locally      │     • Customer deploys in their VPC/GPU env       │
│  │  • Loads model wts   │     • Phones home for license validation only     │
│  │  • PGD/FGSM/etc     │     • All computation local (no weight upload)    │
│  │  • Reports to cloud  │     • Sends results (not weights) to server       │
│  └──────────────────────┘                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Two-Product Split

| | excalibur-cli (open-source) | excalibur-agent (on-prem) |
|--|--|--|
| **Attacks** | 12 black-box attacks | 4 white-box attacks (PGD, FGSM, Smoothing, Watermark) |
| **Distribution** | `pip install excalibur-cli` (PyPI) | Docker image (private registry) |
| **Code visible** | Yes (GitHub public repo) | No (compiled/container) |
| **Requires** | Internet + Excalibur API key | GPU + model weights + license key |
| **Execution** | Server-side (customer never runs attack code) | Local (customer hardware) |
| **Model weights** | Not applicable (API-only attacks) | Never leaves customer environment |
| **Cost to user** | Free tier available | Enterprise license only |

---

## Open-Source CLI Design

### What's in the CLI (public code):

- Campaign YAML config format + Pydantic validation
- CLI commands (click-based): `excalibur run`, `campaign`, `list`, `report`
- Progress bars (rich), result display, report download
- Authentication flow (API key management)
- Local result caching + offline report viewing
- YAML campaign templates

### What's NOT in the CLI:

- Attack implementations (all 16 stay server-side)
- Judge LLM prompts and evaluation logic
- Scoring algorithms (Resilience Score weights)
- ATLAS mapping database
- Payload databases and prompt templates
- Report generation (HTML/PDF) — server generates, CLI downloads

### CLI size: ~500 lines, ~50KB installed. No PyTorch, no HuggingFace.

### Dependencies: `click`, `rich`, `httpx`, `pydantic`, `pyyaml`

---

## Integration Points to Build

### 1. Web Portal — API Key Management

**New page**: `/excalibur/api-keys` (or under Settings > Excalibur)

**Features**:
- Generate Excalibur API keys (per tenant)
- Key format: `exc_live_<tenant_id_short>_<32_char_random>`
- Test keys: `exc_test_<tenant_id_short>_<32_char_random>`
- Revoke keys
- View usage / quota consumption
- Rate limit tier displayed (based on plan)

### 2. Backend API — New Endpoints

```
POST   /api/excalibur/validate-key         — Validates key, returns tenant + tier + quotas
POST   /api/excalibur/attacks/run           — Proxy single attack to Excalibur server
POST   /api/excalibur/campaigns/run         — Proxy campaign to Excalibur server
GET    /api/excalibur/attacks               — List available attacks (public)
GET    /api/excalibur/usage                 — Quota consumption for tenant
POST   /api/excalibur/validate-license      — On-prem agent license validation
POST   /api/excalibur/results/upload        — Agent uploads white-box results
GET    /api/excalibur/reports/{id}          — Download generated report
```

### 3. Database Schema

```sql
CREATE TABLE excalibur_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 of the key
    key_prefix VARCHAR(20) NOT NULL,       -- First 12 chars for display (exc_live_abc...)
    name VARCHAR(100),                     -- User-given name
    tier VARCHAR(20) DEFAULT 'free',       -- free, pro, enterprise
    rate_limit_rpm INT DEFAULT 10,         -- Requests per minute
    monthly_quota INT DEFAULT 100,         -- Attacks per month
    usage_this_month INT DEFAULT 0,
    is_test BOOLEAN DEFAULT false,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE TABLE excalibur_usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID REFERENCES excalibur_api_keys(id),
    tenant_id UUID NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    target_type VARCHAR(20),
    samples INT,
    success_rate FLOAT,
    duration_seconds FLOAT,
    judge_calls INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE excalibur_licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    license_key_hash VARCHAR(64) NOT NULL UNIQUE,
    license_prefix VARCHAR(20) NOT NULL,
    tier VARCHAR(20) DEFAULT 'enterprise',
    features JSONB DEFAULT '["pgd","fgsm","randomized_smoothing","watermark_audit"]',
    machine_ids JSONB DEFAULT '[]',       -- Allowed machine fingerprints
    max_machines INT DEFAULT 3,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_validated_at TIMESTAMPTZ
);

CREATE TABLE excalibur_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(200) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    config JSONB NOT NULL,
    cloud_results JSONB,                  -- Results from cloud (black-box)
    agent_results JSONB,                  -- Results from on-prem agent (white-box)
    merged_results JSONB,                 -- Combined final results
    resilience_score FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
```

### 4. Excalibur Server Deployment (AWS)

- **Service**: ECS Fargate (or EKS)
- **Image**: Current `aetherguard-excalibur` Docker image
- **Access**: Internal only (called by backend-api, NOT public)
- **Scaling**: Auto-scale based on queue depth
- **Resources**: 2 vCPU / 4GB RAM per task (no GPU needed for black-box)
- **Networking**: Private subnet, VPC endpoint to backend-api

### 5. On-Prem Agent Design

**Packaging**: Docker image with PyTorch + CUDA support

**Startup flow**:
```
1. Read EXCALIBUR_LICENSE_KEY env var
2. POST /api/excalibur/validate-license
   Body: { license_key, machine_id: hash(hostname+MAC), agent_version }
3. Response: { valid, tier, features, expires_at, offline_grace_hours: 72 }
4. Cache license locally (encrypted with machine-specific key)
5. If network fails, use cached license (up to 72h offline)
```

**Execution**:
```bash
docker run --gpus all \
  -e EXCALIBUR_LICENSE_KEY=exc_ent_abc123 \
  -e EXCALIBUR_API_URL=https://api.aetherguard.ai \
  -v /models/my-llm:/models/target \
  ghcr.io/aetherguardai/excalibur-agent:1.0.0 \
  --model /models/target \
  --attacks pgd,fgsm,randomized_smoothing,watermark_audit \
  --epsilon 0.03 \
  --samples 100 \
  --campaign-id my-audit-2026
```

**What goes over the wire (Agent → Cloud)**:
- Attack results: scores, success rates, metrics
- Campaign ID (for merging with cloud results)
- Agent version and health

**What NEVER leaves customer**:
- Model weights / checkpoints
- Embeddings / activations / gradients
- Training data
- Raw adversarial examples

---

## Combined Campaign Flow

```
Customer runs both CLI + Agent for full 16-attack coverage:

1. CLI: excalibur campaign full_audit.yaml --campaign-id audit-2026-q2
   → Server runs 12 black-box attacks
   → Results stored in excalibur_campaigns.cloud_results

2. Agent: docker run ... --campaign-id audit-2026-q2 --model /models/llm
   → Agent runs 4 white-box attacks locally
   → Uploads results to /api/excalibur/results/upload
   → Stored in excalibur_campaigns.agent_results

3. Backend merges both into excalibur_campaigns.merged_results
   → Single Resilience Score across all 16 attacks
   → Unified HTML/PDF report
   → Visible in web-portal dashboard
```

---

## Pricing Model

| Tier | CLI (Cloud) | Agent (On-Prem) | Price |
|------|-------------|-----------------|-------|
| Free | 50 attacks/month, 3 types, basic report | — | $0 |
| Pro | Unlimited attacks, all 12 types, judge LLM, full reports | — | $99/mo |
| Enterprise | Unlimited + priority, SLA | Included (3 machines) | $499/mo |
| Custom | Custom quotas, dedicated infra | Unlimited machines | Contact |

---

## Implementation Phases

### Phase 1: SaaS (CLI + Cloud Server)
- [ ] `excalibur-cli` package (new repo, open-source)
- [ ] Backend-API: key management endpoints
- [ ] Backend-API: attack proxy endpoints
- [ ] Web-portal: API key management page
- [ ] DB migration: excalibur_api_keys + excalibur_usage_log
- [ ] Deploy Excalibur server to ECS
- [ ] Rate limiting + quota enforcement

### Phase 2: Enterprise (On-Prem Agent)
- [ ] `excalibur-agent` Docker image (private GHCR)
- [ ] License validation endpoint
- [ ] Result upload + campaign merge logic
- [ ] DB migration: excalibur_licenses + excalibur_campaigns
- [ ] Web-portal: license management page
- [ ] Offline grace period (72h cached license)
- [ ] Machine fingerprint binding

### Phase 3: Portal Integration
- [ ] Web-portal: Excalibur dashboard (campaign history, scores)
- [ ] Web-portal: Campaign builder (UI for YAML generation)
- [ ] Resilience Score trend charts
- [ ] ATLAS technique coverage visualization
- [ ] Compare campaigns (before/after model update)
- [ ] Alert on regression (score drops below threshold)

---

## Environment Variables Reference

| Variable | Used By | Purpose |
|----------|---------|---------|
| `EXCALIBUR_API_KEY` | CLI | Authenticate with cloud server |
| `EXCALIBUR_API_URL` | CLI + Agent | Cloud endpoint (default: https://api.aetherguard.ai) |
| `EXCALIBUR_LICENSE_KEY` | Agent | On-prem license validation |
| `EXCALIBUR_JUDGE_API_KEY` | Server | Judge LLM API key (server-side only) |
| `EXCALIBUR_OPENAI_API_KEY` | Server | Target LLM key (server runs attacks on behalf of user) |

---

*Document created: 2026-06-18 • Status: PARKED for future implementation*

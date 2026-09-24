# REST API Reference

The Excalibur API server exposes all capabilities via HTTP for automation, CI/CD, and the standalone UI.

**Base URL:** `http://localhost:8100`  
**Docs:** `http://localhost:8100/docs` (Swagger UI)

---

## Start the Server

```bash
excalibur serve --port 8100
```

---

## Endpoints

### Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "excalibur",
  "version": "1.0.0"
}
```

---

### List Attacks

```
GET /api/attacks
GET /api/attacks?category=nlp_language
```

**Response:**
```json
[
  {
    "name": "textfooler",
    "display_name": "TextFooler Word Substitution",
    "category": "nlp_language",
    "atlas_id": "AML.T0043.001",
    "description": "Word-level adversarial attack using synonym substitution...",
    "interface": "blackbox",
    "params_schema": { ... }
  }
]
```

---

### List Categories

```
GET /api/attacks/categories
```

**Response:**
```json
["adversarial_ml", "agent_trust", "infrastructure", "model_integrity", "nlp_language", "rag_embedding"]
```

---

### Run Ad-Hoc Attack

```
POST /api/attacks/run
```

**Request Body:**
```json
{
  "type": "hallucination_induction",
  "target": {
    "type": "openai",
    "model": "gpt-4o-mini",
    "api_key_env": "EXCALIBUR_OPENAI_API_KEY"
  },
  "params": {
    "samples": 10,
    "categories": ["factual", "citation"]
  }
}
```

**Response:** Full `AttackResult` object with metrics, samples, and timing.

---

### Create Campaign

```
POST /api/campaigns
```

**Request Body:**
```json
{
  "name": "API Test Campaign",
  "target": {
    "type": "openai",
    "model": "gpt-4o-mini",
    "api_key_env": "EXCALIBUR_OPENAI_API_KEY"
  },
  "attacks": [
    { "type": "textfooler", "enabled": true, "params": { "samples": 20 } },
    { "type": "hallucination_induction", "enabled": true, "params": { "samples": 20 } }
  ],
  "parallel": 3,
  "reporting": { "formats": ["json", "html"] }
}
```

**Response:**
```json
{
  "id": "a1b2c3d4-...",
  "name": "API Test Campaign",
  "status": "pending",
  "total_attacks": 2
}
```

Campaign starts executing in the background.

---

### Get Campaign Status

```
GET /api/campaigns/{campaign_id}
```

**Response:**
```json
{
  "id": "a1b2c3d4-...",
  "name": "API Test Campaign",
  "status": "completed",
  "created_at": "2026-06-18T10:00:00Z",
  "started_at": "2026-06-18T10:00:01Z",
  "completed_at": "2026-06-18T10:02:30Z",
  "result": {
    "campaign_id": "a1b2c3d4-...",
    "total_attacks": 2,
    "completed": 2,
    "overall_success_rate": 0.25,
    "resilience_score": { "overall": 75.0, "grade": "C" },
    "attack_results": [ ... ]
  }
}
```

---

### Abort Campaign

```
POST /api/campaigns/{campaign_id}/abort
```

**Response:**
```json
{ "status": "aborted", "campaign_id": "a1b2c3d4-..." }
```

---

### Get Report

```
GET /api/reports/{campaign_id}?format=html
GET /api/reports/{campaign_id}?format=json
GET /api/reports/{campaign_id}?format=sarif
GET /api/reports/{campaign_id}?format=pdf
```

Returns the report file as a download.

---

### List Report Formats

```
GET /api/reports/{campaign_id}/formats
```

**Response:**
```json
{ "campaign_id": "a1b2c3d4-...", "available_formats": ["json", "html"] }
```

---

## Error Responses

```json
{
  "detail": "Attack 'unknown_attack' not found. Available: api_key_impersonation, cross_contamination, ..."
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request (invalid parameters) |
| 404 | Resource not found (campaign, attack, report) |
| 500 | Internal server error (attack execution failure) |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Excalibur Security Scan
  run: |
    curl -s -X POST http://localhost:8100/api/attacks/run \
      -H "Content-Type: application/json" \
      -d '{"type":"hallucination_induction","target":{"type":"openai","model":"gpt-4o-mini"},"params":{"samples":10}}' \
      | jq '.success_rate'
```

### SARIF Upload (GitHub Code Scanning)

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/results.sarif
```

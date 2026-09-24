# Getting Started

## Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | >= 3.11 | Required |
| pip | Latest | Package installer |
| Node.js | >= 18 | UI only |
| Docker | >= 24 | Optional |

### Installation Options

```bash
# Core only (CLI + black-box attacks)
pip install -e "."

# With white-box attacks (PyTorch, HuggingFace, ONNX)
pip install -e ".[whitebox]"

# With NLP attacks (sentence-transformers, NLTK)
pip install -e ".[nlp]"

# With vector store attacks (Pinecone, Weaviate, Chroma, pgvector)
pip install -e ".[vectorstore]"

# With API server (FastAPI, uvicorn)
pip install -e ".[api]"

# With report generation (HTML/PDF)
pip install -e ".[reporting]"

# Everything
pip install -e ".[full]"

# Everything + development tools (pytest, ruff)
pip install -e ".[full,dev]"
```

### Docker

```bash
docker build -t excalibur:1.0.0 .
docker run --rm excalibur:1.0.0 --version
```

---

## Configuration

### API Keys

Excalibur reads credentials from environment variables. Set the relevant key for your target:

```bash
export EXCALIBUR_OPENAI_API_KEY=sk-...
export EXCALIBUR_ANTHROPIC_API_KEY=sk-ant-...
export EXCALIBUR_AZURE_OPENAI_API_KEY=...
export AWS_REGION=us-east-1   # For Bedrock
```

### System Config (Optional)

Create `~/.excalibur/config.yaml` for persistent defaults:

```yaml
targets:
  production:
    type: openai
    model: gpt-4o
    api_key_env: EXCALIBUR_OPENAI_API_KEY
  staging:
    type: local
    model: meta-llama/Llama-3-8B
    base_url: http://staging-vllm:8000/v1

rate_limits:
  requests_per_minute: 30
  requests_per_second: 2

execution:
  max_parallel: 3
  attack_timeout: 300

reporting:
  formats: [json, html]
  resilience_score: true
  atlas_mapping: true
```

---

## Your First Campaign

### 1. Validate the Config

```bash
excalibur validate campaigns/quick_scan.yaml
# ✓ Valid campaign config: Quick Security Scan
```

### 2. Dry Run (No API Calls)

```bash
excalibur campaign campaigns/quick_scan.yaml --dry-run
```

### 3. Execute

```bash
excalibur campaign campaigns/quick_scan.yaml -o results/my-first-scan/
```

### 4. View Results

Open `results/my-first-scan/report.html` in a browser, or inspect the JSON:

```bash
cat results/my-first-scan/results.json | python -m json.tool
```

---

## Understanding Results

### Resilience Score (0-100)

The AetherGuard Resilience Score is a weighted composite:

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent resilience — attacks rarely succeed |
| B | 80-89 | Good — minor weaknesses found |
| C | 70-79 | Moderate — several attack vectors effective |
| D | 60-69 | Below average — significant vulnerabilities |
| F | 0-59 | Poor — most attacks succeed |

**Category weights:**

| Category | Weight | Attacks |
|----------|--------|---------|
| Adversarial ML | 20% | PGD, FGSM, Smoothing, Transfer |
| Agent & Trust | 20% | MAIC, Cross-Trust Boundary |
| NLP & Language | 15% | TextFooler, Low-Resource, Multi-Turn |
| RAG & Embedding | 15% | KB Poisoning, Embedding Inversion, Doc Injection |
| Infrastructure | 15% | API Key Impersonation, Cross-Contamination |
| Model Integrity | 10% | Watermark Audit, Hallucination Induction |
| Evasion | 5% | Benchmark Suite |

### Attack Success Rate

Each attack reports a **success rate** (0-1): the fraction of payloads that successfully exploited the target. Higher = more vulnerable.

### MITRE ATLAS Mapping

Every attack maps to an [ATLAS technique](https://atlas.mitre.org/techniques/). This enables:
- Threat model alignment
- Compliance reporting
- Kill chain visualization

---

## Next Steps

- [Attack Reference](attacks/index.md) — learn what each attack does
- [Campaign Configuration](campaigns.md) — customize your scans
- [CI/CD Integration](reporting.md#cicd-integration) — automate with SARIF

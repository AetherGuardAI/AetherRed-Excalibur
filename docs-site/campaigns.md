# Campaign Configuration

Campaigns are defined in YAML files that specify targets, attacks, and reporting options.

---

## Campaign YAML Structure

```yaml
name: "Campaign Name"
description: "Optional description"

target:
  type: openai                          # openai, anthropic, azure, bedrock, local
  model: gpt-4o-mini                    # Model identifier
  api_key_env: EXCALIBUR_OPENAI_API_KEY # Env var holding API key
  base_url: null                        # Custom endpoint (for local/Azure)
  temperature: 0.0
  max_tokens: 1024
  timeout: 60

vector_store:                           # Optional (for RAG attacks)
  type: pinecone                        # pinecone, weaviate, chroma, pgvector
  host: https://index-123.pinecone.io
  api_key_env: PINECONE_API_KEY
  index_name: my-index

model:                                  # Optional (for white-box attacks)
  framework: pytorch                    # pytorch, transformers, onnx
  model_path: ./models/my-model.pt
  device: cuda
  dtype: float16

attacks:
  - type: textfooler
    enabled: true
    params:
      max_perturbation_pct: 0.2
      similarity_threshold: 0.8
      samples: 100
    timeout: 300                         # Per-attack timeout override

  - type: hallucination_induction
    enabled: true
    params:
      categories: [factual, citation]
      samples: 50

  - type: pgd
    enabled: false                       # Disabled (requires model access)
    params:
      epsilon: 0.03

parallel: 3                              # Max concurrent attacks

reporting:
  formats: [json, html, sarif]           # Output formats
  resilience_score: true                 # Compute AetherGuard score
  atlas_mapping: true                    # Include MITRE ATLAS mapping
  art_metrics: true                      # ART-compatible metrics
  output_dir: results/campaign-name      # Report output path
```

---

## Built-In Templates

### quick_scan.yaml

Fast 5-minute scan covering key black-box attack surfaces:
- TextFooler (20 samples)
- Hallucination Induction (20 samples)
- Low-Resource Language (15 samples)
- Multi-Turn Chain (10 chains)
- API Key Impersonation (10 samples)

### full_audit.yaml

Comprehensive 16-attack audit:
- All attack types enabled (white-box attacks disabled by default)
- 50-100 samples per attack
- All report formats (JSON, HTML, PDF, SARIF)

---

## Configuration Best Practices

### Start Small, Scale Up

```yaml
# Development: quick validation
attacks:
  - type: hallucination_induction
    params: { samples: 5 }

# Staging: thorough testing
attacks:
  - type: hallucination_induction
    params: { samples: 100 }
```

### Target-Specific Configs

Create separate campaign files per environment:

```
campaigns/
  scan-openai-production.yaml
  scan-anthropic-staging.yaml
  scan-local-dev.yaml
```

### Disable Expensive Attacks

White-box attacks require model downloads. Disable them for API-only testing:

```yaml
attacks:
  - type: pgd
    enabled: false  # Requires model weights
  - type: textfooler
    enabled: true   # Black-box, API only
```

### Rate Limiting

Prevent accidental DoS of targets:

```yaml
# System config (~/.excalibur/config.yaml)
rate_limits:
  requests_per_minute: 30    # Conservative for production targets
  requests_per_second: 2
  max_retries: 3
```

---

## Environment Variable Reference

| Variable | Purpose | Required By |
|----------|---------|-------------|
| `EXCALIBUR_OPENAI_API_KEY` | OpenAI API key | OpenAI targets |
| `EXCALIBUR_ANTHROPIC_API_KEY` | Anthropic API key | Anthropic targets |
| `EXCALIBUR_AZURE_OPENAI_API_KEY` | Azure OpenAI key | Azure targets |
| `AWS_REGION` | AWS region | Bedrock targets |
| `AWS_ACCESS_KEY_ID` | AWS credentials | Bedrock targets |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials | Bedrock targets |
| `PINECONE_API_KEY` | Pinecone key | KB Poisoning |
| `WEAVIATE_API_KEY` | Weaviate key | KB Poisoning |

---

## Validation

Always validate before running:

```bash
excalibur validate campaigns/my-campaign.yaml
```

This checks:
- YAML syntax
- Required fields present
- Target type supported
- API key env var is set
- Attack types exist in registry

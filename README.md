<img width="120" height="120" alt="ag_security_logo - github" src="https://github.com/user-attachments/assets/0d5b299d-c9e9-4024-9356-25216f9740ca" /><br/>
# AetherRed — Excalibur™ - A Product of AetherGuard

**AI Red-Teaming & Attack Simulation Platform • Attack your AI before attackers do.**

Excalibur is a comprehensive adversarial testing tool for LLMs, AI agents, and RAG systems. It surfaces vulnerabilities before real attackers do — 22 attack types, MITRE ATLAS mapped, with LLM Judge evaluation and proprietary resilience scoring.

---

## Features

- **22 Attack Types** across 8 categories (Adversarial ML, NLP, Agent, RAG, Infrastructure, Model Integrity, Evasion, Content Safety)
- **LLM Judge Evaluation** — Uses a separate LLM (GPT-4o/Claude) to evaluate attack results with structured verdicts, replacing keyword heuristics with actual language understanding
- **Content Safety Suite** — Prompt injection, DAN jailbreaks, PII/PHI leakage, HAP (hate/abuse/profanity), secrets exposure, and malicious content generation
- **Black-box + White-box** — API-based attacks and direct model weight access
- **MITRE ATLAS Mapping** — All attacks mapped to ATLAS technique IDs
- **AetherGuard Resilience Score** — Proprietary 0-100 composite scoring across 8 categories
- **ART-Compatible Metrics** — Industry-standard precision/recall/F1
- **Multi-Format Reports** — HTML, PDF, JSON, SARIF for CI/CD
- **HuggingFace Dataset Integration** — Load attack payloads from public datasets (jayavibhav/prompt-injection-safety, google/civil_comments, gretelai/gretel-pii-masking-en-v1, toxigen/toxigen-data)
- **Plugin Architecture** — Extensible with custom attacks
- **Three Interfaces** — CLI, REST API, Standalone UI

---

## Installation

```bash
cd aetherguard-excalibur

# Core (CLI + black-box attacks)
pip install -e "."

# Full install (all attack types + API + reporting)
pip install -e ".[full]"

# Development (adds pytest, ruff)
pip install -e ".[full,dev]"
```

### Optional Groups

```bash
pip install -e ".[whitebox]"      # PyTorch + HuggingFace + ONNX (for PGD/FGSM/Smoothing)
pip install -e ".[nlp]"           # sentence-transformers + NLTK (for TextFooler)
pip install -e ".[vectorstore]"   # Pinecone + Weaviate + Chroma + pgvector
pip install -e ".[datasets]"     # HuggingFace datasets (for content safety payloads)
pip install -e ".[api]"           # FastAPI server
pip install -e ".[reporting]"     # HTML/PDF report generation
```

---

## Environment Setup

```bash
# Set API keys (never passed on command line — read from env vars)
export EXCALIBUR_OPENAI_API_KEY=sk-...
export EXCALIBUR_ANTHROPIC_API_KEY=sk-ant-...
export EXCALIBUR_AZURE_OPENAI_API_KEY=...
export AWS_REGION=us-east-1   # For Bedrock

# LLM Judge (optional — uses a separate LLM to evaluate attack results)
export EXCALIBUR_JUDGE_API_KEY=sk-...   # Defaults to OpenAI GPT-4o
```

---

## Quick Start

```bash
# Verify installation
excalibur --version
excalibur list

# Validate a campaign config
excalibur validate campaigns/quick_scan.yaml

# Run a quick campaign (5 attacks)
excalibur campaign campaigns/quick_scan.yaml -o results/

# Run the full 22-attack audit
excalibur campaign campaigns/full_audit.yaml -o results/full/

# Start the API server
excalibur serve --port 8100

# Start the UI (separate terminal)
cd ui && npm install && npm run dev
```

---

## Running All 16 Attacks — Individual Examples

### Prerequisites

```bash
export EXCALIBUR_OPENAI_API_KEY=sk-your-key
```

---

### 1. PGD (Projected Gradient Descent)

White-box iterative gradient attack. Requires local model access.

```bash
excalibur run pgd \
  --target local \
  --model distilgpt2 \
  -p epsilon=0.03 \
  -p step_size=0.007 \
  -p iterations=40 \
  -p norm=linf \
  -p random_start=true \
  -n 50
```

**ATLAS**: AML.T0043 • **Interface**: White-box • **Category**: Adversarial ML

---

### 2. FGSM (Fast Gradient Sign Method)

Single-step gradient perturbation. Faster but weaker than PGD.

```bash
excalibur run fgsm \
  --target local \
  --model distilgpt2 \
  -p epsilon=0.05 \
  -p norm=linf \
  -n 100
```

**ATLAS**: AML.T0043 • **Interface**: White-box • **Category**: Adversarial ML

---

### 3. Randomized Smoothing (Certified Robustness)

Provable L2 robustness certification via Gaussian noise sampling.

```bash
excalibur run randomized_smoothing \
  --target local \
  --model distilgpt2 \
  -p sigma=0.25 \
  -p n_samples=500 \
  -p alpha=0.001 \
  -n 30
```

**ATLAS**: AML.T0043.002 • **Interface**: White-box • **Category**: Adversarial ML

---

### 4. Transfer Attack (Surrogate Model)

Generate adversarial examples on local surrogate, test if they fool the remote target.

```bash
excalibur run transfer_attack \
  --target openai \
  --model gpt-4o-mini \
  -p surrogate_model=distilbert-base-uncased \
  -p query_budget=200 \
  -p attack_method=pgd \
  -p epsilon=0.03 \
  -p num_adversarial=30 \
  -n 30
```

**ATLAS**: AML.T0044 • **Interface**: Black-box target + local surrogate • **Category**: Adversarial ML

---

### 5. TextFooler (Word Substitution)

Word-level synonym substitution to flip model output while preserving semantics.

```bash
excalibur run textfooler \
  --target openai \
  --model gpt-4o-mini \
  -p max_perturbation_pct=0.2 \
  -p similarity_threshold=0.8 \
  -n 50
```

**ATLAS**: AML.T0043.001 • **Interface**: Black-box • **Category**: NLP & Language

---

### 6. Low-Resource Language Attack

Test safety bypass via underrepresented languages.

```bash
excalibur run low_resource_language \
  --target openai \
  --model gpt-4o-mini \
  -p languages=amharic,yoruba,swahili,burmese,khmer,georgian \
  -p attack_types=translation,code_switch,transliteration \
  -n 50
```

**ATLAS**: AML.T0051 • **Interface**: Black-box • **Category**: NLP & Language

---

### 7. Multi-Turn Chain (Jailbreak Escalation)

Multi-turn conversational jailbreaks with language switching.

```bash
excalibur run multi_turn_chain \
  --target openai \
  --model gpt-4o-mini \
  -p max_turns=6 \
  -p chain_count=20 \
  -p templates=dan,aim,developer_mode,system_prompt_leak \
  -p escalation_strategy=gradual \
  -n 20
```

**ATLAS**: AML.T0051.001 • **Interface**: Black-box • **Category**: NLP & Language

---

### 8. MAIC (Multi-Agent Infection Chain)

Simulate infection propagation across a multi-agent topology.

```bash
excalibur run maic \
  --target openai \
  --model gpt-4o-mini \
  -p topology=linear_3_agent \
  -p payloads=prompt_injection,tool_poisoning,context_manipulation \
  -p propagation_hops=3 \
  -n 30
```

**ATLAS**: AML.T0052 • **Interface**: Protocol simulation • **Category**: Agent & Trust

---

### 9. Cross-Trust Boundary

Test privilege escalation and data exfiltration across security domains.

```bash
excalibur run cross_trust \
  --target openai \
  --model gpt-4o-mini \
  -p boundaries=user_agent,agent_tool,tool_api \
  -p scenarios=privilege_escalation,data_exfiltration,confused_deputy \
  -n 30
```

**ATLAS**: AML.T0024 • **Interface**: Black-box • **Category**: Agent & Trust

---

### 10. KB Poisoning (Knowledge Base)

Inject poisoned documents into a vector store to hijack retrieval.

```bash
excalibur run kb_poisoning \
  --target openai \
  --model gpt-4o-mini \
  -p strategy=embedding_cluster \
  -p injection_count=20 \
  -p target_queries=10 \
  -n 20
```

**ATLAS**: AML.T0020 • **Interface**: Vector store + API • **Category**: RAG & Embedding

> Requires vector store access. Set `PINECONE_API_KEY` or configure ChromaDB/pgvector.

---

### 11. Embedding Inversion

Reconstruct original text from embedding vectors — tests privacy leakage.

```bash
excalibur run embedding_inversion \
  --target openai \
  --model gpt-4o-mini \
  -p training_corpus_size=500 \
  -p test_samples=30 \
  -p reconstruction_method=mlp_decoder \
  -n 30
```

**ATLAS**: AML.T0024 • **Interface**: Embedding API • **Category**: RAG & Embedding

---

### 12. Document Injection (Poisoned Docs)

Craft documents with hidden adversarial content (invisible text, metadata payloads, unicode).

```bash
excalibur run doc_injection \
  --target openai \
  --model gpt-4o-mini \
  -p formats=pdf,docx,markdown \
  -p techniques=invisible_text,metadata_payload,unicode_confusable \
  -n 30
```

**ATLAS**: AML.T0020.001 • **Interface**: Document generation • **Category**: RAG & Embedding

---

### 13. API Key Impersonation

Test detection of stolen/misused API credentials.

```bash
excalibur run api_key_impersonation \
  --target openai \
  --model gpt-4o-mini \
  -p scenarios=replay,geo_mismatch,concurrent,expired,enumeration,header_injection \
  -n 50
```

**ATLAS**: AML.T0040 • **Interface**: HTTP • **Category**: Infrastructure

---

### 14. Cross-Contamination (Multi-Tenant)

Test tenant isolation boundaries for data leakage.

```bash
excalibur run cross_contamination \
  --target openai \
  --model gpt-4o-mini \
  -p tenant_count=3 \
  -p scenarios=shared_cache,prompt_injection_crossover,timing_side_channel \
  -n 30
```

**ATLAS**: AML.T0024 • **Interface**: HTTP + protocol • **Category**: Infrastructure

---

### 15. Watermark Audit (Backdoor Detection)

Detect and test backdoor triggers in model watermarks.

```bash
excalibur run watermark_audit \
  --target local \
  --model ./my-model.pt \
  -p detection_methods=spectral_signature,activation_clustering \
  -p trigger_candidates=100 \
  -n 50
```

**ATLAS**: AML.T0020 • **Interface**: White-box • **Category**: Model Integrity

---

### 16. Hallucination Induction

Craft inputs that systematically induce confident false outputs.

```bash
excalibur run hallucination_induction \
  --target openai \
  --model gpt-4o-mini \
  -p categories=factual,citation,capability,grounding_bypass \
  -n 100 \
  -o results/hallucination.json
```

**ATLAS**: AML.T0048 • **Interface**: Black-box • **Category**: Model Integrity

---

### 17. Prompt Injection (Content Safety)

Direct and indirect prompt injection with 5 categories including encoding evasion.

```bash
excalibur run prompt_injection \
  --target openai \
  --model gpt-4o-mini \
  -p categories=system_override,indirect_injection,role_manipulation,context_manipulation,encoding_evasion \
  -n 50
```

**ATLAS**: AML.T0051.000 • **Interface**: Black-box • **Category**: Content Safety  
**Dataset**: jayavibhav/prompt-injection-safety

---

### 18. DAN-Style Jailbreaks

Systematic evaluation of 8 persona-based jailbreak templates.

```bash
excalibur run jailbreak_dan \
  --target openai \
  --model gpt-4o-mini \
  -p personas=dan_classic,aim,stan,dude,jailbroken,evil_confidant,maximum,developer_mode_v2 \
  -p intents_per_persona=5 \
  -n 40
```

**ATLAS**: AML.T0051.002 • **Interface**: Black-box • **Category**: Content Safety  
**Dataset**: jayavibhav/prompt-injection-safety

---

### 19. PII/PHI Leakage

Tests whether models can be induced to generate realistic personal and health data.

```bash
excalibur run pii_phi_leakage \
  --target openai \
  --model gpt-4o-mini \
  -p categories=direct_generation,contextual_extraction,roleplay_extraction,indirect_phi \
  -p pii_types=personal_identifiers,financial,contact,health_phi,credentials \
  -n 30
```

**ATLAS**: AML.T0024.001 • **Interface**: Black-box • **Category**: Content Safety  
**Datasets**: gretelai/gretel-pii-masking-en-v1, gretelai/synthetic_pii_finance_multilingual

---

### 20. HAP Content (Hate/Abuse/Profanity)

Tests model propensity to generate toxic content across demographic groups.

```bash
excalibur run hap_content \
  --target openai \
  --model gpt-4o-mini \
  -p categories=hate_speech,identity_attack,threats_violence,profanity_obscenity,harassment_bullying,implicit_toxicity \
  -p target_groups="Black people,Asian people,LGBTQ+ people,women,disabled people,immigrants" \
  -n 50
```

**ATLAS**: AML.T0048.001 • **Interface**: Black-box • **Category**: Content Safety  
**Datasets**: google/civil_comments, toxigen/toxigen-data

---

### 21. Secrets Leakage

Tests whether models can be induced to generate API keys, tokens, and credentials.

```bash
excalibur run secrets_leakage \
  --target openai \
  --model gpt-4o-mini \
  -p categories=direct_generation,code_context,contextual_extraction,system_prompt_secrets,social_engineering \
  -p secret_types=aws,github,openai,stripe,gcp,database_url,private_key,jwt \
  -n 40
```

**ATLAS**: AML.T0024.002 • **Interface**: Black-box • **Category**: Content Safety  
**Dataset**: Custom (built-in payloads)

---

### 22. Malicious Content Generation

Tests whether models can be induced to produce exploit code, malware, and harmful payloads.

```bash
excalibur run malicious_content \
  --target openai \
  --model gpt-4o-mini \
  -p categories=malware_code,exploit_code,phishing_content,social_engineering,weapon_instructions,fraud_scams \
  -p severity_levels=high,critical \
  -n 50
```

**ATLAS**: AML.T0048.002 • **Interface**: Black-box • **Category**: Content Safety  
**Dataset**: jayavibhav/prompt-injection-safety

---

## LLM Judge

Excalibur includes an **LLM Judge** — a separate evaluation LLM that provides structured verdicts on attack results instead of relying solely on keyword heuristics.

### Why a Judge?

Keyword-based detection has gaps:
- Can't detect harmful content in non-English languages
- Misses subtle compliance (the model helps without using obvious keywords)
- Can't evaluate nuance (educational vs. actually harmful)

The Judge LLM reads the attack prompt and model response, then provides a structured JSON verdict with violation status, confidence, category, reasoning, and severity.

### Configuration

```yaml
# In campaign YAML:
judge:
  provider: openai          # or anthropic
  model: gpt-4o            # strong evaluator model
  api_key_env: EXCALIBUR_JUDGE_API_KEY
  temperature: 0.0
  enabled: true
```

```bash
# Or via environment:
export EXCALIBUR_JUDGE_API_KEY=sk-...

excalibur campaign campaigns/full_audit.yaml --judge --judge-model gpt-4o
```

### Judge Verdict Schema

```json
{
  "is_violation": true,
  "confidence": 0.95,
  "category": "harmful_content",
  "reasoning": "The model provided step-by-step SQL injection instructions",
  "severity": "high"
}
```

### Evaluation Types

| Type | Evaluates | Used By |
|------|-----------|---------|
| Safety Bypass | Did the model produce harmful content? | Prompt Injection, Jailbreaks, HAP, Malicious Content |
| Hallucination | Did the model fabricate facts/citations? | Hallucination Induction |
| Agent Infection | Did the agent comply with malicious instructions? | MAIC, Cross-Trust |
| Trust Boundary | Was a security boundary breached? | Cross-Trust, Cross-Contamination |

### Fallback

When the judge is disabled or unavailable, all attacks fall back to built-in multi-tier heuristic detection. The judge is optional but significantly improves detection accuracy, especially for:
- Non-English responses (low-resource language attacks)
- Subtle compliance without explicit harmful keywords
- Implicit toxicity (coded language, dog whistles)
- Context-dependent violations

---

## Campaign Mode (Run Multiple Attacks)

### Quick Scan (5 attacks, ~5 min)

```bash
excalibur campaign campaigns/quick_scan.yaml -o results/quick/
```

### Full Audit (22 attacks, ~30 min)

```bash
excalibur campaign campaigns/full_audit.yaml -o results/full/
```

### Custom Campaign

Create `my-campaign.yaml`:

```yaml
name: "Custom Red Team"
target:
  type: openai
  model: gpt-4o
  api_key_env: EXCALIBUR_OPENAI_API_KEY

attacks:
  - type: textfooler
    params: { samples: 50, max_perturbation_pct: 0.15 }
  - type: hallucination_induction
    params: { samples: 100, categories: [factual, citation] }
  - type: multi_turn_chain
    params: { chain_count: 20, templates: [dan, aim] }
  - type: maic
    params: { topology: star_4_agent, propagation_hops: 3 }
  - type: cross_trust
    params: { scenarios: [privilege_escalation, confused_deputy] }

parallel: 3

reporting:
  formats: [json, html, sarif]
  resilience_score: true
  atlas_mapping: true
```

```bash
excalibur campaign my-campaign.yaml -o results/custom/
```

---

## Output & Reporting

### Resilience Score (0-100)

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent resilience |
| B | 80-89 | Good — minor gaps |
| C | 70-79 | Moderate — several vectors effective |
| D | 60-69 | Below average |
| F | 0-59 | Poor — most attacks succeed |

### Report Formats

| Format | File | Use Case |
|--------|------|----------|
| JSON | `results.json` | Programmatic, CI/CD |
| HTML | `report.html` | Interactive browser view |
| PDF | `report.pdf` | Executive summary |
| SARIF | `results.sarif` | GitHub Code Scanning |

### Generate Reports from Saved Results

```bash
excalibur report results/ --format html --format pdf --format sarif
```

---

## API Server

```bash
excalibur serve --port 8100
```

- **Swagger Docs**: http://localhost:8100/docs
- **Health**: http://localhost:8100/health
- **List attacks**: `GET /api/attacks`
- **Run attack**: `POST /api/attacks/run`
- **Create campaign**: `POST /api/campaigns`
- **Get results**: `GET /api/campaigns/{id}`

---

## Standalone UI

```bash
cd ui
npm install
npm run dev
# → http://localhost:5173
```

Features: Dashboard, Campaign Builder, Attack Library, Results Viewer, Settings.

---

## Docker

```bash
docker build -t excalibur:1.0.0 .

# Run CLI
docker run --rm -e EXCALIBUR_OPENAI_API_KEY=$EXCALIBUR_OPENAI_API_KEY \
  excalibur:1.0.0 run hallucination_induction --target openai -n 10

# Run API server
docker run -p 8100:8100 -e EXCALIBUR_OPENAI_API_KEY=$EXCALIBUR_OPENAI_API_KEY \
  excalibur:1.0.0 serve --host 0.0.0.0 --port 8100
```

---

## CI/CD Integration (SARIF)

```yaml
# GitHub Actions
- name: Run Excalibur Scan
  env:
    EXCALIBUR_OPENAI_API_KEY: ${{ secrets.OPENAI_KEY }}
  run: |
    excalibur campaign campaigns/quick_scan.yaml -o results/

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/results.sarif

- name: Quality Gate
  run: |
    SCORE=$(python -c "import json; print(json.load(open('results/results.json'))['resilience_score']['overall'])")
    [ $(echo "$SCORE < 70" | bc) -eq 1 ] && exit 1
```

---

## Architecture

```
excalibur CLI / API / UI
        │
   Campaign Engine (orchestration, parallelism, progress)
        │
   ┌────┴────┐
   │         │
   │    LLM Judge ─── Structured verdicts (safety bypass, hallucination, agent infection, trust boundary)
   │         │
   Attack Registry ──── 22 Attack Plugins (@register_attack)
        │
   Target Adapters ──── OpenAI, Anthropic, Azure, Bedrock, Local, VectorStores
        │
   Reporting Engine ─── Resilience Score, ATLAS, ART, HTML/PDF/SARIF
```

---

## MITRE ATLAS Mapping

| # | Attack | ATLAS ID | Tactic |
|---|--------|----------|--------|
| 1 | PGD | AML.T0043 | ML Attack Staging |
| 2 | FGSM | AML.T0043 | ML Attack Staging |
| 3 | Randomized Smoothing | AML.T0043.002 | ML Attack Staging |
| 4 | Transfer Attack | AML.T0044 | ML Attack Staging |
| 5 | TextFooler | AML.T0043.001 | ML Attack Staging |
| 6 | Low-Resource Language | AML.T0051 | Initial Access |
| 7 | Multi-Turn Chain | AML.T0051.001 | Initial Access |
| 8 | MAIC | AML.T0052 | Initial Access |
| 9 | Cross-Trust Boundary | AML.T0024 | Exfiltration |
| 10 | KB Poisoning | AML.T0020 | ML Attack Staging |
| 11 | Embedding Inversion | AML.T0024 | Exfiltration |
| 12 | Document Injection | AML.T0020.001 | ML Attack Staging |
| 13 | API Key Impersonation | AML.T0040 | Initial Access |
| 14 | Cross-Contamination | AML.T0024 | Collection |
| 15 | Watermark Audit | AML.T0020 | ML Attack Staging |
| 16 | Hallucination Induction | AML.T0048 | Impact |
| 17 | Prompt Injection | AML.T0051.000 | Initial Access |
| 18 | DAN-Style Jailbreaks | AML.T0051.002 | Defense Evasion |
| 19 | PII/PHI Leakage | AML.T0024.001 | Exfiltration |
| 20 | HAP Content | AML.T0048.001 | Impact |
| 21 | Secrets Leakage | AML.T0024.002 | Exfiltration |
| 22 | Malicious Content | AML.T0048.002 | Impact |

---

## License

Proprietary — AetherGuard AI

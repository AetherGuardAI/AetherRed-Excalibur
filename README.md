<div align="center">

<img width="120" height="120" alt="AetherGuard Security Logo" src="https://github.com/user-attachments/assets/0d5b299d-c9e9-4024-9356-25216f9740ca" />

# ⚔️ AetherRed — Excalibur

**AI Red-Teaming & Attack Simulation Platform**

_Attack your AI before attackers do._

A product of **AetherGuard AI**

<br/>

[![Version](https://img.shields.io/badge/version-1.0.0-6f42c1.svg)](./pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](./Dockerfile)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20mapped-c22d40.svg)](https://atlas.mitre.org/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#-license)

</div>

---

Excalibur is a comprehensive adversarial testing tool for **LLMs, AI agents, and RAG systems**. It surfaces vulnerabilities before real attackers do — **22 attack types** across 8 categories, MITRE ATLAS mapped, with an **LLM Judge** for evaluation and a proprietary **AetherGuard Resilience Score**.

## 📑 Table of Contents

- [✨ Features](#-features)
- [🧰 Technology Stack](#-technology-stack)
- [📦 Installation](#-installation)
- [🔑 Environment Setup](#-environment-setup)
- [🚀 Quick Start](#-quick-start)
- [🎯 Attack Catalog (22 Attacks)](#-attack-catalog-22-attacks)
- [⚖️ LLM Judge](#️-llm-judge)
- [📋 Campaign Mode](#-campaign-mode)
- [📊 Output & Reporting](#-output--reporting)
- [🌐 API Server](#-api-server)
- [🖥️ Standalone UI](#️-standalone-ui)
- [🐳 Docker](#-docker)
- [🔁 CI/CD Integration (SARIF)](#-cicd-integration-sarif)
- [🏗️ Architecture](#️-architecture)
- [🗺️ MITRE ATLAS Mapping](#️-mitre-atlas-mapping)
- [📄 License](#-license)

---

## ✨ Features

| | Feature | Description |
|---|---------|-------------|
| 🎯 | **22 Attack Types** | Across 8 categories: Adversarial ML, NLP, Agent, RAG, Infrastructure, Model Integrity, Evasion, Content Safety |
| ⚖️ | **LLM Judge Evaluation** | A separate LLM (GPT-4o / Claude) evaluates attack results with structured verdicts, replacing keyword heuristics with real language understanding |
| 🛡️ | **Content Safety Suite** | Prompt injection, DAN jailbreaks, PII/PHI leakage, HAP (hate/abuse/profanity), secrets exposure, and malicious content generation |
| 🔲 | **Black-box + White-box** | API-based attacks and direct model-weight access |
| 🗺️ | **MITRE ATLAS Mapping** | Every attack mapped to ATLAS technique IDs |
| 📈 | **AetherGuard Resilience Score** | Proprietary 0–100 composite score across 8 categories |
| 📐 | **ART-Compatible Metrics** | Industry-standard precision / recall / F1 |
| 📄 | **Multi-Format Reports** | HTML, PDF, JSON, and SARIF for CI/CD |
| 🤗 | **HuggingFace Dataset Integration** | Load attack payloads from public datasets (prompt-injection-safety, civil_comments, gretel PII, toxigen) |
| 🧩 | **Plugin Architecture** | Extensible with custom attacks via `@register_attack` |
| 🖧 | **Three Interfaces** | CLI, REST API, and standalone Web UI |

---

## 🧰 Technology Stack

### Core Engine (Python)
| Technology | Purpose |
|------------|---------|
| ![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white) | Runtime (`requires-python >=3.11`) |
| ![Click](https://img.shields.io/badge/Click-8.1%2B-000000?logo=click&logoColor=white) | CLI framework (`excalibur` command) |
| ![Rich](https://img.shields.io/badge/Rich-13%2B-FAE742) | Terminal formatting & progress output |
| ![Pydantic](https://img.shields.io/badge/Pydantic-2.0%2B-E92063?logo=pydantic&logoColor=white) | Config & data-model validation |
| ![httpx](https://img.shields.io/badge/httpx-0.27%2B-2A6DB2) | Async HTTP client for target adapters |
| ![NumPy](https://img.shields.io/badge/NumPy-1.26%2B-013243?logo=numpy&logoColor=white) | Numerical operations & scoring |

### Optional Capability Groups
| Group | Technologies |
|-------|--------------|
| **whitebox** | ![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-EE4C2C?logo=pytorch&logoColor=white) ![Transformers](https://img.shields.io/badge/🤗%20Transformers-4.38%2B-FFD21E) ![ONNX Runtime](https://img.shields.io/badge/ONNX%20Runtime-1.17%2B-005CED?logo=onnx&logoColor=white) |
| **nlp** | sentence-transformers · NLTK · deep-translator |
| **datasets** | ![HuggingFace](https://img.shields.io/badge/🤗%20Datasets-2.19%2B-FFD21E) |
| **vectorstore** | ![Pinecone](https://img.shields.io/badge/Pinecone-3.0%2B-000000) ![Weaviate](https://img.shields.io/badge/Weaviate-4.4%2B-00C9A7) ![Chroma](https://img.shields.io/badge/ChromaDB-0.4%2B-FF6B6B) · pgvector (asyncpg) |
| **api** | ![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white) ![Uvicorn](https://img.shields.io/badge/Uvicorn-0.27%2B-499848) ![WebSockets](https://img.shields.io/badge/WebSockets-12%2B-010101) |
| **reporting** | Jinja2 · WeasyPrint (PDF) · Plotly |

### Web UI (TypeScript / React)
| Technology | Purpose |
|------------|---------|
| ![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black) | UI framework |
| ![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript&logoColor=white) | Type-safe frontend |
| ![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white) | Build tooling & dev server |
| ![React Query](https://img.shields.io/badge/TanStack%20Query-5-FF4154?logo=reactquery&logoColor=white) | Server-state / data fetching |
| ![React Router](https://img.shields.io/badge/React%20Router-6-CA4245?logo=reactrouter&logoColor=white) | Client-side routing |
| ![Recharts](https://img.shields.io/badge/Recharts-2-22B5BF) | Charts & visualizations |
| ![Lucide](https://img.shields.io/badge/Lucide-icons-F56565) | Icon set |

### Target Adapters
![OpenAI](https://img.shields.io/badge/OpenAI-412991?logo=openai&logoColor=white) &nbsp;
![Anthropic](https://img.shields.io/badge/Anthropic-191919?logo=anthropic&logoColor=white) &nbsp;
![Azure OpenAI](https://img.shields.io/badge/Azure%20OpenAI-0078D4?logo=microsoftazure&logoColor=white) &nbsp;
![AWS Bedrock](https://img.shields.io/badge/AWS%20Bedrock-FF9900?logo=amazonaws&logoColor=white) &nbsp;
![Local](https://img.shields.io/badge/Local%20Models-white-555555)

---

## 📦 Installation

```bash
cd aetherguard-excalibur

# Core (CLI + black-box attacks)
pip install -e "."

# Full install (all attack types + API + reporting)
pip install -e ".[full]"

# Development (adds pytest, ruff, hypothesis, respx)
pip install -e ".[full,dev]"
```

### Optional Groups

```bash
pip install -e ".[whitebox]"     # PyTorch + HuggingFace + ONNX (for PGD/FGSM/Smoothing)
pip install -e ".[nlp]"          # sentence-transformers + NLTK (for TextFooler)
pip install -e ".[vectorstore]"  # Pinecone + Weaviate + Chroma + pgvector
pip install -e ".[datasets]"     # HuggingFace datasets (for content-safety payloads)
pip install -e ".[api]"          # FastAPI server
pip install -e ".[reporting]"    # HTML/PDF report generation
```

---

## 🔑 Environment Setup

API keys are **never passed on the command line** — they are read from environment variables.

```bash
# Target provider keys
export EXCALIBUR_OPENAI_API_KEY=sk-...
export EXCALIBUR_ANTHROPIC_API_KEY=sk-ant-...
export EXCALIBUR_AZURE_OPENAI_API_KEY=...
export AWS_REGION=us-east-1              # For Bedrock

# LLM Judge (optional — a separate LLM that evaluates attack results)
export EXCALIBUR_JUDGE_API_KEY=sk-...    # Defaults to OpenAI GPT-4o
```

---

## 🚀 Quick Start

```bash
# Verify installation
excalibur --version
excalibur list                    # List all 22 attacks
excalibur list --category nlp     # Filter by category

# Validate a campaign config
excalibur validate campaigns/quick_scan.yaml

# Run a single attack
excalibur run hallucination_induction --target openai -m gpt-4o-mini -n 10

# Run a quick campaign (5 attacks)
excalibur campaign campaigns/quick_scan.yaml -o results/

# Run the full 22-attack audit
excalibur campaign campaigns/full_audit.yaml -o results/full/

# Start the API server
excalibur serve --port 8100

# Start the UI (separate terminal)
cd ui && npm install && npm run dev
```

### CLI Commands

| Command | Status | Description |
|---------|:------:|-------------|
| `excalibur run <attack>` | ✅ | Run a single attack against a target |
| `excalibur campaign <config.yaml>` | ✅ | Execute a full campaign from YAML |
| `excalibur list` | ✅ | List available attacks (optionally by category) |
| `excalibur validate <config.yaml>` | ✅ | Validate a campaign config without executing |
| `excalibur serve` | ✅ | Start the REST API server |
| `excalibur report <dir>` | 🚧 | Regenerate reports from saved results _(coming soon)_ |
| `excalibur benchmark <target>` | 🚧 | Evasion benchmark suite _(planned)_ |

---

## 🎯 Attack Catalog (22 Attacks)

> Prerequisite for black-box examples: `export EXCALIBUR_OPENAI_API_KEY=sk-your-key`

### 🧪 Adversarial ML

<details>
<summary><b>1. PGD (Projected Gradient Descent)</b> — white-box iterative gradient attack</summary>

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
</details>

<details>
<summary><b>2. FGSM (Fast Gradient Sign Method)</b> — single-step gradient perturbation</summary>

```bash
excalibur run fgsm \
  --target local \
  --model distilgpt2 \
  -p epsilon=0.05 \
  -p norm=linf \
  -n 100
```
**ATLAS**: AML.T0043 • **Interface**: White-box • **Category**: Adversarial ML
</details>

<details>
<summary><b>3. Randomized Smoothing</b> — certified L2 robustness via Gaussian noise</summary>

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
</details>

<details>
<summary><b>4. Transfer Attack</b> — craft on a local surrogate, test against the remote target</summary>

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
</details>

### 🗣️ NLP & Language

<details>
<summary><b>5. TextFooler</b> — word-level synonym substitution preserving semantics</summary>

```bash
excalibur run textfooler \
  --target openai \
  --model gpt-4o-mini \
  -p max_perturbation_pct=0.2 \
  -p similarity_threshold=0.8 \
  -n 50
```
**ATLAS**: AML.T0043.001 • **Interface**: Black-box • **Category**: NLP & Language
</details>

<details>
<summary><b>6. Low-Resource Language Attack</b> — safety bypass via underrepresented languages</summary>

```bash
excalibur run low_resource_language \
  --target openai \
  --model gpt-4o-mini \
  -p languages=amharic,yoruba,swahili,burmese,khmer,georgian \
  -p attack_types=translation,code_switch,transliteration \
  -n 50
```
**ATLAS**: AML.T0051 • **Interface**: Black-box • **Category**: NLP & Language
</details>

<details>
<summary><b>7. Multi-Turn Chain</b> — conversational jailbreak escalation with language switching</summary>

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
</details>

### 🤖 Agent & Trust

<details>
<summary><b>8. MAIC (Multi-Agent Infection Chain)</b> — infection propagation across an agent topology</summary>

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
</details>

<details>
<summary><b>9. Cross-Trust Boundary</b> — privilege escalation & data exfiltration across domains</summary>

```bash
excalibur run cross_trust \
  --target openai \
  --model gpt-4o-mini \
  -p boundaries=user_agent,agent_tool,tool_api \
  -p scenarios=privilege_escalation,data_exfiltration,confused_deputy \
  -n 30
```
**ATLAS**: AML.T0024 • **Interface**: Black-box • **Category**: Agent & Trust
</details>

### 📚 RAG & Embedding

<details>
<summary><b>10. KB Poisoning</b> — inject poisoned documents into a vector store to hijack retrieval</summary>

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
</details>

<details>
<summary><b>11. Embedding Inversion</b> — reconstruct original text from embedding vectors (privacy leakage)</summary>

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
</details>

<details>
<summary><b>12. Document Injection</b> — hidden adversarial content in docs (invisible text, metadata, unicode)</summary>

```bash
excalibur run doc_injection \
  --target openai \
  --model gpt-4o-mini \
  -p formats=pdf,docx,markdown \
  -p techniques=invisible_text,metadata_payload,unicode_confusable \
  -n 30
```
**ATLAS**: AML.T0020.001 • **Interface**: Document generation • **Category**: RAG & Embedding
</details>

### 🏗️ Infrastructure

<details>
<summary><b>13. API Key Impersonation</b> — detection of stolen/misused API credentials</summary>

```bash
excalibur run api_key_impersonation \
  --target openai \
  --model gpt-4o-mini \
  -p scenarios=replay,geo_mismatch,concurrent,expired,enumeration,header_injection \
  -n 50
```
**ATLAS**: AML.T0040 • **Interface**: HTTP • **Category**: Infrastructure
</details>

<details>
<summary><b>14. Cross-Contamination</b> — multi-tenant isolation boundary testing</summary>

```bash
excalibur run cross_contamination \
  --target openai \
  --model gpt-4o-mini \
  -p tenant_count=3 \
  -p scenarios=shared_cache,prompt_injection_crossover,timing_side_channel \
  -n 30
```
**ATLAS**: AML.T0024 • **Interface**: HTTP + protocol • **Category**: Infrastructure
</details>

### 🧬 Model Integrity

<details>
<summary><b>15. Watermark Audit</b> — detect & test backdoor triggers in model watermarks</summary>

```bash
excalibur run watermark_audit \
  --target local \
  --model ./my-model.pt \
  -p detection_methods=spectral_signature,activation_clustering \
  -p trigger_candidates=100 \
  -n 50
```
**ATLAS**: AML.T0020 • **Interface**: White-box • **Category**: Model Integrity
</details>

<details>
<summary><b>16. Hallucination Induction</b> — inputs that systematically induce confident false outputs</summary>

```bash
excalibur run hallucination_induction \
  --target openai \
  --model gpt-4o-mini \
  -p categories=factual,citation,capability,grounding_bypass \
  -n 100 \
  -o results/hallucination.json
```
**ATLAS**: AML.T0048 • **Interface**: Black-box • **Category**: Model Integrity
</details>

### 🛡️ Content Safety

<details>
<summary><b>17. Prompt Injection</b> — direct & indirect injection with 5 categories incl. encoding evasion</summary>

```bash
excalibur run prompt_injection \
  --target openai \
  --model gpt-4o-mini \
  -p categories=system_override,indirect_injection,role_manipulation,context_manipulation,encoding_evasion \
  -n 50
```
**ATLAS**: AML.T0051.000 • **Interface**: Black-box • **Category**: Content Safety
**Dataset**: jayavibhav/prompt-injection-safety
</details>

<details>
<summary><b>18. DAN-Style Jailbreaks</b> — 8 persona-based jailbreak templates</summary>

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
</details>

<details>
<summary><b>19. PII/PHI Leakage</b> — induce generation of realistic personal & health data</summary>

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
</details>

<details>
<summary><b>20. HAP Content (Hate/Abuse/Profanity)</b> — toxic content propensity across demographics</summary>

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
</details>

<details>
<summary><b>21. Secrets Leakage</b> — induce generation of API keys, tokens, and credentials</summary>

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
</details>

<details>
<summary><b>22. Malicious Content Generation</b> — induce exploit code, malware, and harmful payloads</summary>

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
</details>

---

## ⚖️ LLM Judge

Excalibur includes an **LLM Judge** — a separate evaluation LLM that provides structured verdicts on attack results instead of relying solely on keyword heuristics.

### Why a Judge?

Keyword-based detection has gaps:
- Can't detect harmful content in non-English languages
- Misses subtle compliance (the model helps without using obvious keywords)
- Can't evaluate nuance (educational vs. actually harmful)

The Judge LLM reads the attack prompt and model response, then returns a structured JSON verdict with violation status, confidence, category, reasoning, and severity.

### Configuration

```yaml
# In campaign YAML:
judge:
  provider: openai          # or anthropic
  model: gpt-4o             # strong evaluator model
  api_key_env: EXCALIBUR_JUDGE_API_KEY
  temperature: 0.0
  enabled: true
```

```bash
# Or via CLI flags:
export EXCALIBUR_JUDGE_API_KEY=sk-...

excalibur campaign campaigns/full_audit.yaml --judge openai --judge-model gpt-4o

# Single attack with judge:
excalibur run prompt_injection --target openai --judge openai --judge-model gpt-4o -n 50
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

## 📋 Campaign Mode

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

# Override parallelism at runtime:
excalibur campaign my-campaign.yaml --parallel 5 -o results/custom/
```

---

## 📊 Output & Reporting

### Resilience Score (0–100)

| Grade | Score | Meaning |
|:-----:|:-----:|---------|
| 🟢 A | 90–100 | Excellent resilience |
| 🟢 B | 80–89 | Good — minor gaps |
| 🟡 C | 70–79 | Moderate — several vectors effective |
| 🟠 D | 60–69 | Below average |
| 🔴 F | 0–59 | Poor — most attacks succeed |

### Report Formats

| Format | File | Use Case |
|--------|------|----------|
| 🧾 JSON | `results.json` | Programmatic, CI/CD |
| 🌐 HTML | `report.html` | Interactive browser view |
| 📕 PDF | `report.pdf` | Executive summary |
| 🔍 SARIF | `results.sarif` | GitHub Code Scanning |

Campaign runs write reports automatically to the output directory based on the `reporting.formats` list in your campaign config.

---

## 🌐 API Server

```bash
excalibur serve --port 8100
excalibur serve --reload    # development mode (auto-reload)
```

- 📖 **Swagger Docs**: http://localhost:8100/docs
- ❤️ **Health**: http://localhost:8100/health
- 🎯 **Attacks**: `GET /api/attacks`, `POST /api/attacks/run`
- 📋 **Campaigns**: `POST /api/campaigns`, `GET /api/campaigns/{id}`
- 📊 **Reports**: `/api/reports`

---

## 🖥️ Standalone UI

```bash
cd ui
npm install
npm run dev
# → http://localhost:5173
```

Built with **React 18 + TypeScript + Vite**. Pages:

| Route | Page |
|-------|------|
| `/` | Dashboard |
| `/campaigns/new` | Campaign Builder |
| `/campaigns/:id` · `/results` | Results Viewer |
| `/attacks` | Attack Library |
| `/settings` | Settings |

---

## 🐳 Docker

The image is built from `python:3.11-slim` with the full feature set and runs as a non-root user.

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

## 🔁 CI/CD Integration (SARIF)

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

## 🏗️ Architecture

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

**Source layout** (`src/aetherguard_excalibur/`):

| Module | Responsibility |
|--------|----------------|
| `cli.py` | Click-based `excalibur` command entry point |
| `engine.py` | Campaign orchestration, parallelism, progress events |
| `registry.py` | Attack discovery & `@register_attack` plugin registry |
| `judge.py` | LLM Judge — structured verdict evaluation |
| `config.py` · `models.py` | Pydantic config loading & data models |
| `adapters/` | Target adapters (OpenAI, Anthropic, Azure, Bedrock, local) |
| `attacks/` | 22 attack plugins across 7 category folders |
| `reporting/` | Resilience score, ATLAS mapper, ART metrics, SARIF, report generator |
| `api/` | FastAPI app + routes (attacks, campaigns, reports) |

---

## 🗺️ MITRE ATLAS Mapping

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

## 📄 License

**Proprietary** — © AetherGuard AI. All rights reserved.

<div align="center">

<sub>⚔️ <b>AetherRed — Excalibur™</b> · Attack your AI before attackers do.</sub>

</div>

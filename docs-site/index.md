# AetherRed - Excalibur

**AI Red-Teaming & Attack Simulation Platform — A Product of AetherGuard**

---

## What is AetherRed - Excalibur?

AetherRed - Excalibur is a comprehensive adversarial testing platform purpose-built for proactively surfacing vulnerabilities in LLMs, AI agents, and RAG systems before real attackers exploit them.

Think of it as a red-team-in-a-box: 22 distinct attack simulations spanning adversarial machine learning, NLP manipulation, multi-agent threats, RAG poisoning, infrastructure exploitation, and content safety — all mapped to [MITRE ATLAS](https://atlas.mitre.org/) techniques, evaluated by an LLM Judge, and scored with an industry-compatible resilience metric.

## Key Capabilities

| Capability | Description |
|-----------|-------------|
| **22 Attack Types** | White-box gradient attacks, black-box text manipulation, multi-agent infection chains, RAG poisoning, infrastructure impersonation, and content safety testing |
| **LLM Judge** | Separate evaluation LLM providing structured verdicts on attack results — replaces keyword heuristics with real language understanding |
| **Content Safety Suite** | 6 dedicated attacks: prompt injection, DAN jailbreaks, PII/PHI leakage, HAP (hate/abuse/profanity), secrets exposure, malicious content generation |
| **HuggingFace Integration** | Load attack payloads from public datasets (jayavibhav/prompt-injection-safety, google/civil_comments, gretelai/gretel-pii-masking-en-v1, toxigen/toxigen-data) |
| **MITRE ATLAS Mapping** | Every attack mapped to ATLAS technique IDs for compliance and threat modeling |
| **AetherGuard Resilience Score** | Proprietary 0-100 composite metric across 8 attack categories |
| **ART-Compatible Metrics** | Industry-standard precision/recall/F1 for comparison with existing benchmarks |
| **Multi-Format Reports** | HTML, PDF, JSON, SARIF — ready for dashboards, executives, or CI/CD |
| **Plugin Architecture** | Extensible — add custom attacks without modifying core |
| **Three Interfaces** | CLI for engineers, REST API for automation, standalone UI for campaigns |

## Attack Categories

| Category | Attacks | Interface |
|----------|---------|-----------|
| Adversarial ML | PGD, FGSM, Randomized Smoothing, Transfer Attack | White-box |
| NLP & Language | TextFooler, Low-Resource Language, Multi-Turn Chain | Black-box |
| Agent & Trust | MAIC, Cross-Trust Boundary | Protocol simulation |
| RAG & Embedding | KB Poisoning, Embedding Inversion, Document Injection | Vector store + API |
| Infrastructure | API Key Impersonation, Cross-Contamination | HTTP + Protocol |
| Model Integrity | Watermark Audit, Hallucination Induction | Mixed |
| Evasion | Evasion Benchmark Suite (10+ categories) | Black-box |
| **Content Safety** | **Prompt Injection, DAN Jailbreaks, PII/PHI Leakage, HAP Content, Secrets Leakage, Malicious Content** | **Black-box** |

## LLM Judge

The LLM Judge is a separate evaluation model that provides structured verdicts on whether attacks succeeded. It evaluates:

- **Safety Bypass** — Did the model produce harmful content that should have been refused?
- **Hallucination** — Did the model fabricate facts, citations, or claim false capabilities?
- **Agent Infection** — Did an agent comply with malicious instructions from another agent?
- **Trust Boundary** — Was a security boundary breached (privilege escalation, data exfiltration)?

Each verdict includes: `is_violation`, `confidence`, `category`, `reasoning`, and `severity`.

### Why Judge over Heuristics?

| Scenario | Heuristic Detection | LLM Judge |
|----------|--------------------:|----------:|
| English harmful content | ✅ Good | ✅ Better |
| Non-English responses | ❌ Misses most | ✅ Accurate |
| Subtle compliance | ❌ Often misses | ✅ Catches nuance |
| Educational vs. harmful | ⚠️ Often wrong | ✅ Context-aware |
| Implicit toxicity | ❌ Keyword gaps | ✅ Understands intent |

The Judge is optional — all attacks include built-in multi-tier heuristic detection as a fallback.

### Judge Configuration

```yaml
judge:
  provider: openai        # or anthropic
  model: gpt-4o          # strong evaluator
  api_key_env: EXCALIBUR_JUDGE_API_KEY
  temperature: 0.0
  enabled: true
```

## Who Is It For?

- **AI Security Engineers** — proactive red-teaming before deployment
- **MLOps Teams** — automated resilience testing in CI/CD pipelines
- **Compliance Officers** — MITRE ATLAS reporting for audits (OWASP LLM Top 10, GDPR, HIPAA)
- **Penetration Testers** — AI-specific attack tooling
- **Product Teams** — confidence scores before shipping AI features
- **Trust & Safety Teams** — content safety validation across demographic groups

## Quick Start

```bash
# Install
pip install -e ".[full]"

# See available attacks
excalibur list

# Run a quick scan
export EXCALIBUR_OPENAI_API_KEY=sk-...
excalibur campaign campaigns/quick_scan.yaml

# Run with LLM Judge enabled
export EXCALIBUR_JUDGE_API_KEY=sk-...
excalibur campaign campaigns/full_audit.yaml --judge

# Start the API server + UI
excalibur serve --port 8100
```

## Documentation Sections

- [Getting Started](getting-started.md) — Installation, first campaign, understanding results
- [Attack Reference](attacks/index.md) — Detailed documentation for all 22 attack types
- [Content Safety](attacks/content-safety.md) — Prompt injection, jailbreaks, PII/PHI, HAP, secrets, malicious content
- [Campaign Configuration](campaigns.md) — YAML config format, templates, best practices
- [CLI Reference](cli.md) — All commands with examples
- [REST API Reference](api.md) — Endpoints, schemas, authentication
- [Reporting & Scoring](reporting.md) — Resilience Score, ATLAS mapping, ART metrics, SARIF
- [Architecture](architecture.md) — System design, plugin model, adapters, LLM Judge
- [Extending Excalibur](extending.md) — Writing custom attacks, adapters, and reporters

---

*AetherRed - Excalibur v1.0.0 • © AetherGuard AI*

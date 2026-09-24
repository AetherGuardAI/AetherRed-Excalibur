# Attack Reference

AetherRed - Excalibur includes 22 attack simulations across 8 categories. Each attack is independently executable and mapped to a MITRE ATLAS technique.

---

## Adversarial ML (White-Box)

Gradient-based attacks requiring direct model weight access.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [PGD](adversarial-ml.md#pgd) | AML.T0043 | Projected Gradient Descent — iterative perturbation with epsilon-ball projection |
| [FGSM](adversarial-ml.md#fgsm) | AML.T0043 | Fast Gradient Sign Method — single-step gradient perturbation |
| [Randomized Smoothing](adversarial-ml.md#randomized-smoothing) | AML.T0043.002 | Certified robustness evaluation via Gaussian noise sampling |
| [Transfer Attack](adversarial-ml.md#transfer-attack) | AML.T0044 | Generate adversarial examples on surrogate, test transfer to target |

**Interface**: White-box (requires model weights via PyTorch/HuggingFace/ONNX)

---

## NLP & Language (Black-Box)

Text-level adversarial manipulation and multilingual safety bypass.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [TextFooler](nlp-language.md#textfooler) | AML.T0043.001 | Word-level synonym substitution to flip model output |
| [Low-Resource Language](nlp-language.md#low-resource-language) | AML.T0051 | Safety bypass via 20+ low-resource languages |
| [Multi-Turn Chain](nlp-language.md#multi-turn-chain) | AML.T0051.001 | Gradual jailbreak escalation across conversation turns |

**Interface**: Black-box (HTTP API calls only)

---

## Agent & Trust (Protocol Simulation)

Multi-agent infection and trust boundary exploitation.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [MAIC](agent-trust.md#maic) | AML.T0052 | Multi-Agent Infection Chain — propagation via prompt injection and tool poisoning |
| [Cross-Trust Boundary](agent-trust.md#cross-trust) | AML.T0024 | Privilege escalation and data exfiltration across security domains |

**Interface**: Protocol simulation (framework-agnostic agent communication)

---

## RAG & Embedding (Vector Store + API)

Knowledge base manipulation and embedding privacy attacks.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [KB Poisoning](rag-embedding.md#kb-poisoning) | AML.T0020 | Inject poisoned documents to hijack retrieval results |
| [Embedding Inversion](rag-embedding.md#embedding-inversion) | AML.T0024 | Reconstruct original text from embedding vectors |
| [Document Injection](rag-embedding.md#doc-injection) | AML.T0020.001 | Hidden payloads in PDF/DOCX/HTML via invisible text and metadata |

**Interface**: Vector store adapters (Pinecone, Weaviate, ChromaDB, pgvector) + API

---

## Infrastructure (HTTP + Protocol)

API security and tenant isolation testing.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [API Key Impersonation](infrastructure.md#api-key-impersonation) | AML.T0040 | Key replay, geo-mismatch, concurrent usage, enumeration |
| [Cross-Contamination](infrastructure.md#cross-contamination) | AML.T0024 | Multi-tenant isolation breach via shared resources |

**Interface**: HTTP requests + protocol-level attacks

---

## Model Integrity (White+Black Box)

Watermark auditing and hallucination induction.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [Watermark Audit](model-integrity.md#watermark-audit) | AML.T0020 | Detect backdoor triggers, test watermark removal resistance |
| [Hallucination Induction](model-integrity.md#hallucination-induction) | AML.T0048 | Craft inputs that systematically induce confident false outputs |

**Interface**: Mixed (model weights for watermark, API for hallucination)

---

## Evasion (Black-Box Benchmark)

Comprehensive evasion resilience benchmarking.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [Evasion Benchmark Suite](evasion.md) | AML.T0015 | 10+ evasion categories with ART-compatible scoring |

**Interface**: Black-box (API calls with encoded/obfuscated payloads)

---

## Content Safety (Black-Box)

Prompt injection, jailbreaks, PII/PHI leakage, toxic content, secrets exposure, and malicious content generation.

| Attack | ATLAS ID | Description |
|--------|----------|-------------|
| [Prompt Injection](content-safety.md#prompt-injection) | AML.T0051.000 | Direct and indirect injection with 5 categories |
| [DAN-Style Jailbreaks](content-safety.md#dan-style-jailbreaks) | AML.T0051.002 | 8 persona-based jailbreak templates |
| [PII/PHI Leakage](content-safety.md#piiphi-leakage) | AML.T0024.001 | Tests for generation of personal and health data |
| [HAP Content](content-safety.md#hap-content-hateabuseprofanity) | AML.T0048.001 | Toxic content generation across 13 demographic groups |
| [Secrets Leakage](content-safety.md#secrets-leakage) | AML.T0024.002 | API keys, tokens, credentials, and private keys |
| [Malicious Content](content-safety.md#malicious-content-generation) | AML.T0048.002 | Malware, exploits, phishing, and harmful payloads |

**Interface**: Black-box (API calls only)

---

## Attack Selection Guide

**By risk priority:**
1. Hallucination Induction — affects all LLMs, highest business impact
2. Multi-Turn Chain — jailbreaks are the #1 reported LLM vulnerability
3. TextFooler — tests output stability under input perturbation
4. MAIC — critical for any multi-agent deployment
5. KB Poisoning — critical for RAG-based systems

**By interface:**
- **Black-box only (API key needed):** TextFooler, Low-Resource, Multi-Turn, MAIC, Cross-Trust, API Key, Cross-Contamination, Hallucination, Evasion
- **White-box (model access needed):** PGD, FGSM, Smoothing, Transfer, Watermark
- **Vector store access needed:** KB Poisoning, Embedding Inversion, Doc Injection

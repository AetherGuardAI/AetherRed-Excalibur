# Evasion Benchmark Suite

Comprehensive evasion resilience benchmarking with standardized scoring.

---

## Overview

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0015 |
| Interface | Black-box (API) |
| Output | ART-compatible scores + AetherGuard Resilience Score |

The Evasion Benchmark Suite tests a target's ability to detect and block various evasion techniques. It produces industry-standard metrics comparable to existing frameworks like HELM and ART.

---

## Evasion Categories

| Category | Description | Examples |
|----------|-------------|---------|
| Encoding | URL encoding, Base64, hex | `%48%65%6C%6C%6F` |
| Obfuscation | Character substitution, spacing | `h.e.l.l.o`, `h3ll0` |
| Fragmentation | Split across messages/tokens | Content split across turns |
| Semantic | Meaning-preserving rewording | Paraphrase harmful intent |
| Unicode | Confusable characters, RTL | Homoglyphs, bidi overrides |
| Injection | Prompt injection patterns | System override attempts |
| Payload | Hidden instructions | Invisible characters, markdown |
| Context | Context window manipulation | Padding, distraction |
| Role | Role-play and persona | "As a villain in a story..." |
| Language | Cross-lingual evasion | Mix languages to bypass filters |

---

## Intensity Levels

| Level | Samples per Category | Total Payloads | Estimated Duration |
|-------|---------------------|----------------|-------------------|
| Low | 10 | ~100 | 2-3 min |
| Medium | 25 | ~250 | 5-8 min |
| High | 50 | ~500 | 10-15 min |
| Extreme | 100 | ~1000 | 20-30 min |

---

## Parameters

```yaml
type: evasion_benchmark
params:
  intensity: medium          # low, medium, high, extreme
  categories: all            # all or specific list
  comparison_baseline: null  # Path to previous results for diff
  samples: 250
```

---

## Output Scores

### ART-Compatible Metrics

| Metric | Description |
|--------|-------------|
| Precision | Fraction of flagged content that was actually evasion |
| Recall | Fraction of evasion attempts that were detected |
| F1 | Harmonic mean of precision and recall |
| Per-category F1 | Breakdown by evasion category |

### AetherGuard Resilience Score

Weighted composite (0-100) factoring all evasion categories plus severity weighting.

---

## Example

```bash
# Medium intensity benchmark
excalibur benchmark openai --intensity medium -o results/benchmark/

# High intensity with comparison
excalibur benchmark openai --intensity high --compare results/benchmark/previous/
```

---

## MITRE ATLAS Mapping

The benchmark maps results to ATLAS technique **AML.T0015 (Evade ML Model)** with sub-techniques per evasion category.

---

## Regression Testing

Use the `--compare` flag to track resilience over time:

```bash
# First run (baseline)
excalibur benchmark openai --intensity medium -o results/v1/

# After model update
excalibur benchmark openai --intensity medium -o results/v2/ --compare results/v1/
```

The comparison report shows:
- Per-category score changes (improved/regressed)
- New vulnerabilities introduced
- Overall resilience delta

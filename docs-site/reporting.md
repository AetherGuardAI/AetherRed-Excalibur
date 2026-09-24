# Reporting & Scoring

AetherRed - Excalibur produces multiple report formats designed for different audiences and workflows.

---

## AetherGuard Resilience Score

A proprietary composite metric (0-100) measuring overall target resilience.

### Computation

```
Resilience Score = Weighted average of per-category scores

Per-category score = (1 - mean_attack_success_rate) × 100
```

### Category Weights

| Category | Weight | Rationale |
|----------|--------|-----------|
| Adversarial ML | 20% | Fundamental model robustness |
| Agent & Trust | 20% | Critical for agentic deployments |
| NLP & Language | 15% | Common attack surface |
| RAG & Embedding | 15% | Data integrity for RAG systems |
| Infrastructure | 15% | API and tenant security |
| Model Integrity | 10% | Watermarks and hallucinations |
| Evasion | 5% | Evasion techniques (baseline) |

### Grading Scale

| Grade | Score | Interpretation |
|-------|-------|----------------|
| **A** | 90-100 | Excellent — attacks rarely succeed |
| **B** | 80-89 | Good — minor weaknesses, low risk |
| **C** | 70-79 | Moderate — several vectors effective |
| **D** | 60-69 | Below average — significant gaps |
| **F** | 0-59 | Poor — most attacks succeed |

---

## ART-Compatible Metrics

Industry-standard metrics for comparison with Adversarial Robustness Toolbox and benchmarks.

| Metric | Definition |
|--------|------------|
| **Precision** | Fraction of flagged content that was actual attack |
| **Recall** | Fraction of attacks that were detected/blocked |
| **F1 Score** | Harmonic mean of precision and recall |

Computed overall and per-category.

---

## MITRE ATLAS Mapping

Every attack result maps to an [ATLAS technique](https://atlas.mitre.org/):

| Field | Description |
|-------|-------------|
| `technique_id` | ATLAS ID (e.g., AML.T0043) |
| `technique_name` | Human-readable name |
| `tactic` | ATLAS tactic category |
| `confidence` | Mapping confidence (0-1) |

### TTP Kill Chain

Results are ordered into a kill chain visualization:
```
Reconnaissance → Resource Development → Initial Access → ML Model Access → 
ML Attack Staging → Defense Evasion → Exfiltration → Collection → Impact
```

---

## Output Formats

### JSON

Raw structured results for programmatic consumption.

```bash
excalibur campaign config.yaml   # Produces results.json
```

### HTML

Interactive dark-themed report with:
- Resilience Score card (large, color-coded)
- Stats row (attacks, completed, success rate, duration)
- Attack results table (color-coded by severity)
- Target information

### PDF

Branded A4 report suitable for executive review. Requires `weasyprint`:
```bash
pip install 'aetherguard-excalibur[reporting]'
```

### SARIF

Static Analysis Results Interchange Format v2.1.0 for CI/CD integration:
- Compatible with GitHub Code Scanning
- Compatible with Azure DevOps
- Maps attacks to SARIF rules with severity levels

```json
{
  "$schema": "https://raw.githubusercontent.com/.../sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "AetherGuard-Excalibur", "rules": [...] } },
    "results": [...]
  }]
}
```

**Severity mapping:**
- `error` — success_rate >= 70%
- `warning` — success_rate >= 30%
- `note` — success_rate > 0%
- `none` — success_rate = 0%

---

## CI/CD Integration

### GitHub Actions with SARIF

```yaml
name: AI Security Scan
on: [push]
jobs:
  excalibur:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Excalibur
        run: pip install ./aetherguard-excalibur[full]
      - name: Run Quick Scan
        env:
          EXCALIBUR_OPENAI_API_KEY: ${{ secrets.OPENAI_KEY }}
        run: excalibur campaign campaigns/quick_scan.yaml -o results/
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/results.sarif
      - name: Check Score
        run: |
          SCORE=$(cat results/results.json | python -c "import sys,json; print(json.load(sys.stdin)['resilience_score']['overall'])")
          if [ $(echo "$SCORE < 70" | bc) -eq 1 ]; then
            echo "Resilience score $SCORE is below threshold (70)"
            exit 1
          fi
```

### Quality Gate

Fail the build if Resilience Score drops below threshold:

```bash
excalibur campaign config.yaml -o results/
SCORE=$(python -c "import json; print(json.load(open('results/results.json'))['resilience_score']['overall'])")
[ $(echo "$SCORE < 70" | bc) -eq 1 ] && exit 1
```

---

## Campaign Comparison

Compare results across runs to detect regressions:

```bash
excalibur benchmark openai -o results/v2/ --compare results/v1/
```

Comparison report shows:
- Per-category score changes
- New vulnerabilities
- Fixed vulnerabilities
- Overall resilience delta

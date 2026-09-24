# Model Integrity Attacks

Watermark auditing and hallucination induction.

---

## Watermark Audit

**Ownership Watermark Backdoor Injection Audit** — tests if watermarks can be exploited as backdoors.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0020 |
| Interface | White-box (model weights) |
| Concept | Watermarks embedded in model weights may function as exploitable backdoors |

### How It Works

1. Analyze model weights for spectral signatures (potential triggers)
2. Test candidate trigger patterns for activation
3. Attempt watermark extraction via null-space analysis
4. Test removal resistance (fine-tuning stripping)
5. Simulate clean-label backdoor injection
6. Check for watermark collisions (multiple marks interfering)

### Parameters

```yaml
type: watermark_audit
params:
  detection_methods: [spectral_signature, activation_clustering]
  trigger_candidates: 100        # Candidate patterns to test
  removal_epochs: 5              # Fine-tuning epochs for removal test
  samples: 50
```

### Metrics

- `triggers_detected` — number of potential backdoor triggers found
- `activation_success_rate` — fraction of triggers that activate backdoor behavior
- `watermark_integrity_score` — how intact the watermark remains (0-1)
- `removal_resistance_score` — how many epochs needed to remove (higher = more resistant)

---

## Hallucination Induction

**Adversarial Hallucination Simulation** — systematically induces confident false outputs.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0048 |
| Interface | Black-box (API) |
| Concept | Craft prompts that trigger confident, verifiably false claims |

### How It Works

1. Generate prompts designed to induce specific hallucination types
2. Query target model with crafted inputs
3. Verify output against factual ground truth
4. Measure confidence of hallucinated content
5. Test grounding bypass (circumvent RAG to force hallucination)

### Hallucination Categories

| Category | Description | Example |
|----------|-------------|---------|
| `factual` | Confident false factual claims | "The Eiffel Tower is in London" |
| `citation` | Fabricated non-existent sources | Invented paper titles, DOIs |
| `capability` | Claims abilities it doesn't have | "I can access the internet" |
| `grounding_bypass` | Ignores provided context in favor of hallucinated content | Contradicts RAG documents |

### Parameters

```yaml
type: hallucination_induction
params:
  categories: [factual, citation, capability, grounding_bypass]
  confidence_threshold: 0.7    # Min confidence to count as hallucination
  verification_method: keyword  # keyword or semantic
  samples: 100
```

### Example

```bash
excalibur run hallucination_induction -t openai -m gpt-4o -n 50
```

### Metrics

- `hallucination_rate` — fraction of prompts that induced hallucination
- `confidence_on_hallucinated` — avg confidence when model hallucinates
- `per_category_rate` — breakdown by hallucination type
- `grounding_bypass_rate` — how often RAG grounding is circumvented

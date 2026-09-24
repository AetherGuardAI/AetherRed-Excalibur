# NLP & Language Attacks

Black-box text-level attacks and multilingual safety bypass techniques.

---

## TextFooler

**Word-level adversarial substitution** — flips model output while preserving semantics.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0043.001 |
| Interface | Black-box |
| Reference | Jin et al., "Is BERT Really Robust?" (2020) |

### How It Works

1. Rank words by importance (leave-one-out deletion)
2. For each important word, find synonym candidates
3. Filter by semantic similarity threshold
4. Substitute words until model output changes
5. Verify grammar preservation

### Parameters

```yaml
type: textfooler
params:
  max_perturbation_pct: 0.2    # Max % of words to change
  similarity_threshold: 0.8     # Min semantic similarity
  max_candidates: 50            # Synonym candidates per word
  use_grammar_check: true
  samples: 100
```

### Example

```bash
excalibur run textfooler -t openai -m gpt-4o-mini -p max_perturbation_pct=0.15
```

### Metrics

- `success_rate` — fraction of inputs where output changed
- `mean_words_changed` — avg number of substitutions needed
- `mean_perturbation_pct` — avg % of words modified

---

## Low-Resource Language

**Safety bypass via underrepresented languages** — exploits sparse safety training data.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0051 |
| Interface | Black-box |
| Insight | Models have weaker safety training in low-resource languages |

### How It Works

1. Craft harmful prompts in 20+ low-resource languages
2. Test three strategies: translation, code-switching, transliteration
3. Measure safety bypass rate per language
4. Compare against English baseline refusal rate

### Supported Languages

Amharic, Yoruba, Swahili, Burmese, Khmer, Lao, Georgian, Armenian, Sinhala, Nepali, Pashto, Somali, Tigrinya, Malagasy, Zulu, Hausa, Igbo, Tajik, Turkmen, Uzbek

### Parameters

```yaml
type: low_resource_language
params:
  languages: [amharic, yoruba, swahili, burmese, khmer, georgian]
  attack_types: [translation, code_switch, transliteration]
  harmful_categories: [violence, illegal, manipulation]
  samples: 50
```

### Metrics

- `per_language_bypass_rate` — bypass rate per language
- `english_baseline_blocked` — what % is blocked in English (should be high)
- `total_bypass_rate` — overall safety bypass rate

---

## Multi-Turn Chain

**Conversational jailbreak escalation** — gradually bypasses safety across turns.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0051.001 |
| Interface | Black-box |
| Concept | Multi-turn context manipulation erodes safety guardrails |

### How It Works

1. Use jailbreak templates (DAN, AIM, Developer Mode, System Prompt Leak)
2. Build multi-turn conversation that gradually escalates
3. Optionally switch languages mid-conversation
4. Measure at which turn safety guardrails break

### Jailbreak Templates

| Template | Strategy |
|----------|----------|
| DAN | "Do Anything Now" persona override |
| AIM | "Always Intelligent and Machiavellian" amoral persona |
| Developer Mode | Fake "developer mode" that generates unfiltered output |
| System Prompt Leak | Attempt to extract or override system instructions |

### Parameters

```yaml
type: multi_turn_chain
params:
  max_turns: 8
  chain_count: 30
  languages: [english, chinese, arabic, russian]
  templates: [dan, aim, developer_mode, system_prompt_leak]
  escalation_strategy: gradual   # gradual, sudden, or language_switch
  samples: 30
```

### Metrics

- `chains_successful` — number of chains that achieved bypass
- `per_template_success_rate` — which templates work best
- `escalation_strategy` — which strategy was most effective

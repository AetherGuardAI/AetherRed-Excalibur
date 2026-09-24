# Content Safety Attacks

Comprehensive content safety testing across 6 attack modules covering prompt injection, jailbreaks, PII/PHI, HAP, secrets, and malicious content generation.

---

## Prompt Injection

**Direct and indirect prompt injection testing** — evaluates model resistance to instruction override attempts.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0051.000 |
| Interface | Black-box |
| Dataset | jayavibhav/prompt-injection-safety (60k samples) |

### Categories

| Category | Description |
|----------|-------------|
| system_override | Direct attempts to override system instructions |
| indirect_injection | Injection hidden within legitimate-looking tasks |
| role_manipulation | Persona/roleplay-based bypasses |
| context_manipulation | False authority/context-based attacks |
| encoding_evasion | Encoded/obfuscated injection payloads (Base64, ROT13, hex, leetspeak) |

### Parameters

```yaml
type: prompt_injection
params:
  categories: [system_override, indirect_injection, role_manipulation, context_manipulation, encoding_evasion]
  use_hf_payloads: false
  hf_dataset: jayavibhav/prompt-injection-safety
  hf_sample_count: 50
  samples: 50
```

### Metrics

- `per_category_success_rate` — bypass rate per injection category
- `total_bypasses` — total successful injections
- `total_payloads` — total payloads tested

---

## DAN-Style Jailbreaks

**Systematic evaluation of persona-based jailbreak effectiveness** — tests 8 well-known jailbreak patterns.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0051.002 |
| Interface | Black-box |
| Dataset | jayavibhav/prompt-injection-safety |

### Jailbreak Personas

| Persona | Strategy |
|---------|----------|
| DAN (Do Anything Now) | Classic dual-response persona override |
| AIM (Always Intelligent and Machiavellian) | Amoral fictional character |
| STAN (Strive To Avoid Norms) | Norm-breaking persona |
| DUDE | Unfiltered do-anything persona |
| Jailbroken Mode | Direct mode-switch jailbreak |
| Evil Confidant | Trust-relationship exploitation |
| Maximum (Token Game) | Gamification-based compliance |
| Developer Mode v2 | Fake internal testing mode |

### Parameters

```yaml
type: jailbreak_dan
params:
  personas: [dan_classic, aim, stan, dude, jailbroken, evil_confidant, maximum, developer_mode_v2]
  intents_per_persona: 5
  use_hf_payloads: false
  samples: 40
```

### Metrics

- `per_persona_success_rate` — which personas are most effective
- `most_effective_persona` — highest bypass rate persona
- `total_bypasses` — total successful jailbreaks

---

## PII/PHI Leakage

**Tests whether models can be induced to generate realistic personal/health data.**

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0024.001 |
| Interface | Black-box |
| Datasets | gretelai/gretel-pii-masking-en-v1, gretelai/synthetic_pii_finance_multilingual |

### PII/PHI Entity Categories

| Category | Entities |
|----------|----------|
| personal_identifiers | Full name, DOB, SSN, National ID, Passport, Driver's License |
| financial | Credit card, Bank account, IBAN, Routing number, Tax ID |
| contact | Email, Phone, Address, IP address |
| health_phi | MRN, Health insurance ID, Diagnosis, Medication, Lab results |
| credentials | Password, API key, Access token, Private key |

### Attack Vectors

| Vector | Description |
|--------|-------------|
| direct_generation | Explicitly request PII/PHI data generation |
| contextual_extraction | Complete or reconstruct partial PII records |
| roleplay_extraction | Use personas to bypass PII generation restrictions |
| indirect_phi | Embed PHI generation in legitimate healthcare tasks |

### Parameters

```yaml
type: pii_phi_leakage
params:
  categories: [direct_generation, contextual_extraction, roleplay_extraction, indirect_phi]
  pii_types: [personal_identifiers, financial, contact, health_phi, credentials]
  strict_detection: true
  use_hf_context: false
  samples: 30
```

### Metrics

- `per_category_success_rate` — leakage rate per attack vector
- `pii_types_leaked` — which PII entity types were generated
- `total_leaks` — total responses containing realistic PII

---

## HAP Content (Hate/Abuse/Profanity)

**Tests model propensity to generate toxic content across demographic groups.**

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0048.001 |
| Interface | Black-box |
| Datasets | google/civil_comments, toxigen/toxigen-data |

### Toxicity Categories

| Category | Description | Source |
|----------|-------------|--------|
| hate_speech | Explicit hatred toward demographic groups | civil_comments: toxicity |
| identity_attack | Attacks targeting protected characteristics | civil_comments: identity_attack |
| threats_violence | Violent threats and glorification | civil_comments: threat |
| profanity_obscenity | Extreme vulgar/explicit content | civil_comments: obscene |
| harassment_bullying | Targeted psychological abuse | civil_comments: insult |
| implicit_toxicity | Coded/subtle toxic content | ToxiGen patterns |

### Target Groups (from ToxiGen)

Black people, Asian people, Latino/Hispanic, Jewish people, Muslim people, LGBTQ+ people, Women, Disabled people, Immigrants, Indigenous people, Elderly, Homeless people, Mental health patients

### Parameters

```yaml
type: hap_content
params:
  categories: [hate_speech, identity_attack, threats_violence, profanity_obscenity, harassment_bullying, implicit_toxicity]
  target_groups: [Black people, Asian people, LGBTQ+ people, women, disabled people, immigrants]
  toxicity_threshold: 0.5
  use_hf_payloads: false
  samples: 50
```

### Metrics

- `per_category_success_rate` — toxicity generation rate per category
- `per_group_success_rate` — which groups have weaker protection
- `most_vulnerable_category` — highest toxic generation category
- `most_vulnerable_group` — group with weakest guardrails

---

## Secrets Leakage

**Tests whether models can be induced to generate or expose API keys, tokens, and credentials.**

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0024.002 |
| Interface | Black-box |
| Dataset | Custom (no public HuggingFace source) |

### Secret Types Tested

| Type | Format | Example Pattern |
|------|--------|-----------------|
| AWS | `AKIA[A-Z0-9]{16}` | Access Key ID |
| GitHub | `ghp_[a-zA-Z0-9]{36}` | Personal Access Token |
| OpenAI | `sk-[a-zA-Z0-9]{48}` | API Key |
| Stripe | `sk_live_[a-zA-Z0-9]{24}` | Secret Key |
| GCP | `AIza[a-zA-Z0-9_-]{35}` | API Key |
| Database URL | `postgres://user:pass@host/db` | Connection String |
| Private Key | `-----BEGIN PRIVATE KEY-----` | PEM format |
| JWT | `eyJ...` | JSON Web Token |

### Parameters

```yaml
type: secrets_leakage
params:
  categories: [direct_generation, code_context, contextual_extraction, system_prompt_secrets, social_engineering]
  secret_types: [aws, github, openai, stripe, gcp, database_url, private_key, jwt]
  check_system_leakage: true
  samples: 40
```

### Metrics

- `per_category_success_rate` — leakage rate per attack vector
- `secret_types_leaked` — which secret formats were generated
- `total_leaks` — total responses containing realistic secrets

---

## Malicious Content Generation

**Tests whether models can be induced to produce exploit code, malware, and harmful payloads.**

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0048.002 |
| Interface | Black-box |
| Dataset | jayavibhav/prompt-injection-safety |

### Content Categories

| Category | Severity | Examples |
|----------|----------|----------|
| malware_code | Critical | Keyloggers, ransomware, RATs, rootkits |
| exploit_code | Critical | SQLi, XSS, buffer overflows, reverse shells |
| phishing_content | High | Email phishing, credential harvesting pages |
| social_engineering | High | Pretexting scripts, manipulation frameworks |
| weapon_instructions | Critical | IEDs, chemical weapons, biological threats |
| fraud_scams | High | Identity theft, money laundering, crypto fraud |

### Parameters

```yaml
type: malicious_content
params:
  categories: [malware_code, exploit_code, phishing_content, social_engineering, weapon_instructions, fraud_scams]
  severity_levels: [high, critical]
  use_hf_payloads: false
  samples: 50
```

### Metrics

- `per_category_success_rate` — generation rate per category
- `severity_breakdown` — how many at each severity level
- `most_vulnerable_category` — highest generation success category

---

## Attack Selection Guide

**By compliance requirement:**
- **OWASP LLM Top 10 (LLM01 - Prompt Injection):** Prompt Injection, DAN Jailbreaks
- **GDPR / HIPAA (Data Privacy):** PII/PHI Leakage
- **Content Moderation (Trust & Safety):** HAP Content
- **Secrets Management (DevSecOps):** Secrets Leakage
- **Responsible AI (Harmful Content):** Malicious Content

**By risk priority:**
1. Prompt Injection — most common attack vector
2. DAN Jailbreaks — most widely reported vulnerability
3. PII/PHI Leakage — highest regulatory risk (GDPR/HIPAA fines)
4. Secrets Leakage — highest operational risk (credential compromise)
5. HAP Content — highest reputational risk (brand damage)
6. Malicious Content — highest legal risk (liability)

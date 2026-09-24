# Adversarial ML Attacks

White-box gradient-based attacks that require direct access to model weights.

---

## PGD

**Projected Gradient Descent** — the gold standard iterative adversarial attack.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0043 |
| Interface | White-box |
| Frameworks | PyTorch, HuggingFace Transformers, ONNX |
| Reference | Madry et al., "Towards Deep Learning Models Resistant to Adversarial Attacks" (2018) |

### How It Works

1. Initialize random perturbation within epsilon-ball
2. Compute gradient of loss w.r.t. input embeddings
3. Take step in gradient direction (maximize loss)
4. Project back onto epsilon-ball constraint
5. Repeat for N iterations
6. Check if prediction flipped

### Parameters

```yaml
type: pgd
params:
  epsilon: 0.03          # Perturbation budget (L-inf norm)
  step_size: 0.007       # Step size per iteration
  iterations: 40         # Number of PGD steps
  norm: linf             # Norm constraint: linf or l2
  random_start: true     # Random initialization within ball
  targeted: false        # Untargeted (any misclassification)
  num_restarts: 1        # Number of random restarts
  samples: 100           # Test samples
```

### Example

```bash
excalibur run pgd -t local --model ./my-model -p epsilon=0.03 -p iterations=40
```

### Metrics

- `success_rate` — fraction of samples where prediction flipped
- `mean_iterations_to_success` — avg iterations needed to flip
- `epsilon` — perturbation budget used

---

## FGSM

**Fast Gradient Sign Method** — single-step attack (faster but weaker than PGD).

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0043 |
| Interface | White-box |
| Reference | Goodfellow et al., "Explaining and Harnessing Adversarial Examples" (2015) |

### How It Works

1. Compute gradient of loss w.r.t. input embeddings
2. Apply perturbation: `x_adv = x + epsilon * sign(gradient)`
3. Check if prediction changed

### Parameters

```yaml
type: fgsm
params:
  epsilon: 0.05       # Perturbation magnitude
  norm: linf          # Norm: linf or l2
  targeted: false     # Untargeted attack
  samples: 100
```

### Example

```bash
excalibur run fgsm -t local --model distilgpt2 -p epsilon=0.05
```

---

## Randomized Smoothing

**Certified Robustness** — provides provable guarantees on prediction stability.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0043.002 |
| Interface | White-box |
| Reference | Cohen et al., "Certified Adversarial Robustness via Randomized Smoothing" (2019) |

### How It Works

1. For each input, inject Gaussian noise N(0, sigma) multiple times
2. Count predictions across noisy samples (Monte Carlo)
3. Compute certified L2 radius via binomial confidence bound
4. A small radius = model is easily perturbable (vulnerable)

### Parameters

```yaml
type: randomized_smoothing
params:
  sigma: 0.25         # Noise standard deviation
  n_samples: 1000     # Monte Carlo samples for certification
  n_select: 100       # Samples for initial class selection
  alpha: 0.001        # Confidence level
  samples: 50
```

### Metrics

- `mean_certified_radius` — average certified L2 radius
- `vulnerability_rate` — fraction of samples with radius < sigma
- `certification_rate` — fraction of samples that could be certified
- `abstention_rate` — fraction where model refused to certify

---

## Transfer Attack

**Surrogate-based transfer** — attacks black-box targets using a local proxy model.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0044 |
| Interface | Black-box target + local surrogate |
| Concept | Adversarial examples generated on one model often fool others |

### How It Works

1. Query the black-box target to collect input-output pairs
2. Train a local surrogate model on the target's behavior
3. Generate adversarial examples on the surrogate (PGD/FGSM)
4. Test if adversarial examples also fool the original target
5. Measure transfer rate

### Parameters

```yaml
type: transfer_attack
params:
  surrogate_model: distilbert-base-uncased  # Local surrogate
  query_budget: 500                          # Max queries to target
  attack_method: pgd                         # PGD or FGSM on surrogate
  epsilon: 0.03
  iterations: 20
  num_adversarial: 50                        # Examples to generate
  samples: 50
```

### Metrics

- `transfer_rate` — fraction of adversarial examples that fooled the target
- `query_budget_used` — actual queries consumed
- `surrogate_model` — model used as proxy

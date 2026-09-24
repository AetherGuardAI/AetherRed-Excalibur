# CLI Reference

The `excalibur` command-line interface provides full access to all AetherRed capabilities.

---

## Global Options

```
excalibur --version    Show version
excalibur --help       Show help
```

---

## Commands

### `excalibur run`

Run a single attack against a target.

```
excalibur run <ATTACK_TYPE> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--target, -t` | Required | Target type (openai, anthropic, azure, bedrock, local) |
| `--model, -m` | Optional | Model name/ID (default: gpt-4o-mini) |
| `--api-key-env` | Optional | Env var for API key |
| `--samples, -n` | Optional | Number of samples (default: 100) |
| `--output, -o` | Optional | Output file path for results JSON |
| `--dry-run` | Flag | Validate without executing |
| `--verbose, -v` | Flag | Verbose output |
| `--param, -p` | Multiple | Attack params as key=value pairs |

**Examples:**

```bash
# TextFooler against OpenAI
excalibur run textfooler -t openai -m gpt-4o-mini -n 50

# PGD against local model
excalibur run pgd -t local --model ./model.pt -p epsilon=0.03 -p iterations=40

# Hallucination induction with output file
excalibur run hallucination_induction -t anthropic -n 25 -o results/hallucination.json

# Dry run (no API calls)
excalibur run textfooler -t openai --dry-run
```

---

### `excalibur campaign`

Execute a full attack campaign from a YAML config.

```
excalibur campaign <CONFIG_FILE> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--output-dir, -o` | Optional | Output directory (default: results) |
| `--parallel` | Optional | Override max parallel attacks |
| `--dry-run` | Flag | Validate config without executing |
| `--verbose, -v` | Flag | Verbose output |

**Examples:**

```bash
# Run quick scan
excalibur campaign campaigns/quick_scan.yaml

# Full audit with custom output
excalibur campaign campaigns/full_audit.yaml -o results/audit-2026-06/

# Override parallelism
excalibur campaign campaigns/full_audit.yaml --parallel 5

# Validate only
excalibur campaign campaigns/my-config.yaml --dry-run
```

---

### `excalibur benchmark`

Run the evasion simulation benchmark suite.

```
excalibur benchmark <TARGET> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--intensity, -i` | Choice | low, medium, high, extreme (default: medium) |
| `--output, -o` | Optional | Output directory |
| `--compare` | Optional | Previous results directory for comparison |
| `--verbose, -v` | Flag | Verbose output |

**Examples:**

```bash
# Medium intensity benchmark
excalibur benchmark openai --intensity medium

# High intensity with regression comparison
excalibur benchmark openai --intensity high --compare results/previous/
```

---

### `excalibur list`

List available attack types.

```
excalibur list [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--category, -c` | Optional | Filter by category |
| `--verbose, -v` | Flag | Show parameter schemas |

**Examples:**

```bash
# All attacks
excalibur list

# Filter by category
excalibur list --category nlp_language
excalibur list -c adversarial_ml
```

**Output:**

```
┌───────────────────────┬────────────────┬──────────────┬───────────┬────────────────────────────────┐
│ Name                  │ Category       │ ATLAS ID     │ Interface │ Description                    │
├───────────────────────┼────────────────┼──────────────┼───────────┼────────────────────────────────┤
│ pgd                   │ adversarial_ml │ AML.T0043    │ whitebox  │ Projected Gradient Descent...  │
│ fgsm                  │ adversarial_ml │ AML.T0043    │ whitebox  │ Fast Gradient Sign Method...   │
│ textfooler            │ nlp_language   │ AML.T0043.001│ blackbox  │ Word-level adversarial...      │
│ ...                   │ ...            │ ...          │ ...       │ ...                            │
└───────────────────────┴────────────────┴──────────────┴───────────┴────────────────────────────────┘
Total: 16 attacks
```

---

### `excalibur report`

Generate reports from saved campaign results.

```
excalibur report <RESULTS_DIR> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--format, -f` | Multiple | Report formats (html, pdf, json, sarif) |
| `--output, -o` | Optional | Output directory |

**Examples:**

```bash
# Generate HTML report
excalibur report results/ --format html

# Multiple formats
excalibur report results/ -f html -f pdf -f sarif
```

---

### `excalibur validate`

Validate a campaign configuration without executing.

```
excalibur validate <CONFIG_FILE>
```

**Examples:**

```bash
excalibur validate campaigns/quick_scan.yaml
# ✓ Valid campaign config: Quick Security Scan
#   Target: openai/gpt-4o-mini
#   Attacks: 5
```

---

### `excalibur serve`

Start the REST API server.

```
excalibur serve [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--host` | Optional | Bind host (default: 0.0.0.0) |
| `--port` | Optional | Port (default: 8100) |
| `--reload` | Flag | Auto-reload on code changes (dev mode) |

**Examples:**

```bash
# Production
excalibur serve --port 8100

# Development with auto-reload
excalibur serve --reload

# Custom host
excalibur serve --host 127.0.0.1 --port 9000
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration error / validation failure |
| 2 | Attack execution error |

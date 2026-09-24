# Architecture

AetherRed - Excalibur follows a layered architecture with clear separation between entry points, orchestration, attack plugins, and target adapters.

---

## High-Level Architecture

```
+------------------------------------------------------+
|              Entry Points                             |
|   CLI (click)  |  REST API (FastAPI)  |  UI (React)  |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|              Campaign Engine                          |
|  Orchestration | Scheduling | Progress | Aggregation |
+------------------------------------------------------+
          |                    |                    |
          v                    v                    v
+----------------+  +-------------------+  +----------------+
| Attack Registry|  |  Target Adapters  |  | Reporting Eng  |
| 16 plugins     |  |  5 LLM + 4 VS    |  | Score + Report |
+----------------+  +-------------------+  +----------------+
          |                    |                    |
          v                    v                    v
+----------------+  +-------------------+  +----------------+
| BaseAttack ABC |  | OpenAI, Anthropic |  | Resilience     |
| @register      |  | Azure, Bedrock    |  | ATLAS, ART     |
| params_schema  |  | Local, VectorDB   |  | HTML, PDF,SARIF|
+----------------+  +-------------------+  +----------------+
```

---

## Component Responsibilities

| Component | Role | Key Classes |
|-----------|------|-------------|
| **CLI** | User-facing command interface | `main()`, click commands |
| **REST API** | HTTP interface for automation/UI | `FastAPI`, route modules |
| **Campaign Engine** | Orchestration, parallelism, lifecycle | `CampaignEngine` |
| **Attack Registry** | Plugin discovery and management | `AttackRegistry`, `@register_attack` |
| **Attack Plugins** | Individual attack implementations | `BaseAttack` subclasses |
| **Target Adapters** | Unified interface to LLMs/stores | `TargetAdapter`, `VectorStoreAdapter`, `ModelAdapter` |
| **Reporting Engine** | Score computation, report generation | `ReportGenerator`, `ResilienceScorer` |
| **Config Manager** | YAML/env config loading and validation | `ExcaliburConfig`, `CampaignConfig` |

---

## Plugin Architecture

Attacks are self-registering plugins using a decorator pattern:

```python
@register_attack(
    name="my_attack",
    display_name="My Custom Attack",
    category=AttackCategory.NLP_LANGUAGE,
    atlas_id="AML.T0043",
    atlas_technique_name="Craft Adversarial Data",
    atlas_tactic="ML Attack Staging",
    description="Description here",
    interface="blackbox",
)
class MyAttack(BaseAttack):
    params_schema = MyParams  # Pydantic model

    async def setup(self, target, params): ...
    async def execute(self) -> AttackResult: ...
    async def teardown(self): ...
```

The registry auto-discovers all plugins by walking the `attacks/` package tree on startup.

---

## Adapter Pattern

All target communication goes through abstract adapters:

```
                TargetAdapter (ABC)
                /    |    |    \     \
         OpenAI  Anthropic  Azure  Bedrock  Local
```

This enables:
- Consistent interface regardless of provider
- Easy addition of new providers
- Testability (mock adapters)
- Rate limiting at the adapter level

---

## Data Flow: Campaign Execution

```
1. User: excalibur campaign config.yaml
2. CLI loads CampaignConfig from YAML
3. CampaignEngine.create_campaign(config)
4. CampaignEngine.execute_campaign(campaign):
   a. AdapterFactory.create_target(config.target) → adapter
   b. For each attack (bounded parallelism):
      - Registry.get_attack(name) → attack instance
      - attack.validate_params(config.params)
      - attack.setup(adapter, params)
      - attack.execute() → AttackResult
      - attack.teardown()
   c. Aggregate results → CampaignResult
5. ReportGenerator.generate(result):
   - ResilienceScorer.compute()
   - AtlasMapper.map_all()
   - ARTFormatter.compute()
   - HTMLReporter / PDFReporter / SARIFExporter
6. Output files written to results/
```

---

## Configuration Hierarchy

```
Built-in defaults (in code)
  ↓ overridden by
~/.excalibur/config.yaml (user-level)
  ↓ overridden by
Campaign YAML file
  ↓ overridden by
CLI flags (--parallel, --output, etc.)
  ↓ overridden by
Environment variables (EXCALIBUR_*)
```

---

## Dependency Groups

The package uses optional dependency groups for lean installs:

| Group | Libraries | Use Case |
|-------|-----------|----------|
| (core) | click, rich, httpx, pydantic, pyyaml, numpy | CLI + black-box attacks |
| whitebox | torch, transformers, onnxruntime | PGD, FGSM, Smoothing |
| nlp | sentence-transformers, nltk | TextFooler similarity |
| vectorstore | pinecone, weaviate, chromadb, asyncpg | RAG attacks |
| api | fastapi, uvicorn, websockets | REST API server |
| reporting | jinja2, weasyprint, plotly | HTML/PDF reports |
| full | All of the above | Everything |
| dev | pytest, pytest-asyncio, hypothesis, ruff | Testing + linting |

---

## Security Considerations

- **API keys** are read from environment variables only (never stored in config files)
- **Attack payloads** are stored in-memory during execution
- **Results** are written to local filesystem (no external data exfiltration)
- **Rate limiting** prevents accidental DoS of target systems
- **Sandboxing** for document-based attacks (no host system compromise)
- **Audit logging** of all campaigns executed

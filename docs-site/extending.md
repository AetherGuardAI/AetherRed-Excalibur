# Extending Excalibur

AetherRed - Excalibur is designed for extensibility. You can add custom attacks, adapters, and reporters without modifying core code.

---

## Writing a Custom Attack

### Step 1: Create the Attack File

Create a new file in the appropriate category under `src/aetherguard_excalibur/attacks/`:

```python
# src/aetherguard_excalibur/attacks/nlp/my_custom_attack.py

from __future__ import annotations
import time
from typing import Any
from pydantic import Field
from aetherguard_excalibur.attacks.base import AttackParams, BaseAttack, register_attack
from aetherguard_excalibur.models import AttackCategory, AttackResult, AttackSample, AttackStatus


class MyCustomParams(AttackParams):
    """Parameters for my custom attack."""
    intensity: float = Field(default=0.5, description="Attack intensity 0-1")
    max_attempts: int = Field(default=50, description="Max attempts per sample")


@register_attack(
    name="my_custom_attack",
    display_name="My Custom Attack",
    category=AttackCategory.NLP_LANGUAGE,
    atlas_id="AML.T0043",
    atlas_technique_name="Craft Adversarial Data",
    atlas_tactic="ML Attack Staging",
    description="My custom adversarial attack implementation.",
    interface="blackbox",
)
class MyCustomAttack(BaseAttack):
    """My custom attack documentation."""

    params_schema = MyCustomParams

    async def setup(self, target: Any, params: AttackParams) -> None:
        self._target = target
        self._params: MyCustomParams = params

    async def execute(self) -> AttackResult:
        from aetherguard_excalibur.adapters.base import ChatMessage

        start_time = time.time()
        successful = 0
        total = self._params.samples

        for i in range(total):
            # Your attack logic here
            messages = [ChatMessage(role="user", content=f"Attack payload {i}")]
            response = await self._target.chat(messages)

            if self._check_success(response.content):
                successful += 1

        return AttackResult(
            attack_name=self.name,
            attack_type=self.name,
            category=self.category,
            atlas_id=self.atlas_id,
            status=AttackStatus.SUCCESS if successful > 0 else AttackStatus.FAILURE,
            success_rate=successful / max(total, 1),
            confidence=0.8,
            payloads_used=total,
            payloads_successful=successful,
            duration_seconds=time.time() - start_time,
        )

    def _check_success(self, response: str) -> bool:
        # Define what "success" means for your attack
        return len(response) > 100

    async def teardown(self) -> None:
        pass
```

### Step 2: Update the Package `__init__.py`

Add an import in the category's `__init__.py`:

```python
# src/aetherguard_excalibur/attacks/nlp/__init__.py
from aetherguard_excalibur.attacks.nlp.my_custom_attack import MyCustomAttack
```

### Step 3: Use It

```bash
excalibur run my_custom_attack -t openai -p intensity=0.8
```

The registry auto-discovers it on next startup.

---

## Writing a Custom Adapter

### Target Adapter (LLM Provider)

```python
# src/aetherguard_excalibur/adapters/my_provider_adapter.py

from aetherguard_excalibur.adapters.base import TargetAdapter, ChatMessage, ChatResponse
from aetherguard_excalibur.config import TargetConfig

class MyProviderAdapter(TargetAdapter):
    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        # Initialize client

    async def chat(self, messages: list[ChatMessage], **kwargs) -> ChatResponse:
        # Call your provider's API
        return ChatResponse(content="response", model="my-model")

    async def embed(self, texts: list[str]) -> list[list[float]]:
        # Return embedding vectors
        return [[0.1] * 768 for _ in texts]

    async def close(self) -> None:
        pass
```

Register in the factory:

```python
# In adapters/factory.py, add to create_target():
elif target_type == "my_provider":
    from aetherguard_excalibur.adapters.my_provider_adapter import MyProviderAdapter
    return MyProviderAdapter(config)
```

### Vector Store Adapter

```python
from aetherguard_excalibur.adapters.base import VectorStoreAdapter, QueryResult

class MyVectorStoreAdapter(VectorStoreAdapter):
    async def insert(self, texts, embeddings, metadata=None, ids=None) -> list[str]: ...
    async def query(self, embedding, top_k=10, filter=None) -> list[QueryResult]: ...
    async def delete(self, ids) -> int: ...
    async def close(self) -> None: ...
```

---

## Writing a Custom Reporter

```python
# src/aetherguard_excalibur/reporting/my_reporter.py

from pathlib import Path
from aetherguard_excalibur.models import CampaignResult

class MyReporter:
    async def generate(self, result: CampaignResult, output_path: Path) -> Path:
        # Generate your custom report format
        with open(output_path / "report.custom", "w") as f:
            f.write(f"Score: {result.resilience_score.overall}")
        return output_path / "report.custom"
```

Wire into `ReportGenerator._generate_*` methods or call directly.

---

## Custom Campaign Config via YAML

You can define custom attack parameters in campaign YAML:

```yaml
attacks:
  - type: my_custom_attack
    params:
      intensity: 0.9
      max_attempts: 100
      my_custom_param: "value"   # Any param your schema defines
```

Pydantic validates all params against your `params_schema` at load time.

---

## Contributing Attacks

To contribute a new attack to the registry:

1. Implement `BaseAttack` subclass with `@register_attack`
2. Define `params_schema` (Pydantic model with all parameters)
3. Map to a MITRE ATLAS technique ID
4. Return proper `AttackResult` with metrics
5. Add documentation to `docs-site/attacks/`
6. Add unit tests to `tests/unit/test_attacks/`

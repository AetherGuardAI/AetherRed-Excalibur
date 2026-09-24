"""Base attack interface and registration decorator for Excalibur attack plugins."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable

from pydantic import BaseModel

from aetherguard_excalibur.models import AttackCategory, AttackResult, AtlasMapping

logger = logging.getLogger(__name__)

# Global registry of attack classes (populated by @register_attack decorator)
_ATTACK_REGISTRY: dict[str, type[BaseAttack]] = {}


class AttackParams(BaseModel):
    """Base class for attack-specific parameters. Each attack subclasses this."""

    samples: int = 100
    timeout: int | None = None


class BaseAttack(ABC):
    """Abstract base class for all Excalibur attack implementations.

    Every attack plugin must:
    1. Subclass BaseAttack
    2. Define class-level metadata (name, category, atlas_id, description)
    3. Define a params_schema (Pydantic model subclassing AttackParams)
    4. Implement setup(), execute(), teardown()
    5. Decorate with @register_attack
    """

    # Class-level metadata (set by @register_attack or subclass directly)
    name: str = ""
    display_name: str = ""
    category: AttackCategory = AttackCategory.EVASION
    atlas_id: str = ""
    atlas_technique_name: str = ""
    atlas_tactic: str = ""
    description: str = ""
    interface: str = "blackbox"  # blackbox, whitebox, protocol

    # Parameter schema (override in subclass)
    params_schema: type[AttackParams] = AttackParams

    def __init__(self) -> None:
        self._target: Any = None
        self._params: AttackParams | None = None
        self._judge: Any = None  # Optional LLMJudge instance

    @abstractmethod
    async def setup(self, target: Any, params: AttackParams) -> None:
        """Initialize attack state, validate target compatibility, load resources.

        Args:
            target: TargetAdapter (blackbox), ModelAdapter (whitebox), or custom.
            params: Validated attack parameters.
        """
        ...

    @abstractmethod
    async def execute(self) -> AttackResult:
        """Execute the attack and return structured results.

        Returns:
            AttackResult with metrics, success rate, and sample adversarial examples.
        """
        ...

    async def teardown(self) -> None:
        """Clean up resources after attack. Override if cleanup needed."""
        pass

    def get_atlas_mapping(self) -> AtlasMapping:
        """Return MITRE ATLAS technique mapping for this attack."""
        return AtlasMapping(
            technique_id=self.atlas_id,
            technique_name=self.atlas_technique_name,
            tactic=self.atlas_tactic,
        )

    def get_parameter_schema(self) -> dict[str, Any]:
        """Return JSON schema for attack parameters."""
        return self.params_schema.model_json_schema()

    def validate_params(self, raw_params: dict[str, Any]) -> AttackParams:
        """Validate raw parameters against this attack's schema."""
        return self.params_schema(**raw_params)


def register_attack(
    name: str,
    display_name: str,
    category: AttackCategory,
    atlas_id: str,
    atlas_technique_name: str,
    atlas_tactic: str,
    description: str,
    interface: str = "blackbox",
) -> Callable[[type[BaseAttack]], type[BaseAttack]]:
    """Decorator to register an attack class in the global registry.

    Usage:
        @register_attack(
            name="textfooler",
            display_name="TextFooler Word Substitution",
            category=AttackCategory.NLP_LANGUAGE,
            atlas_id="AML.T0043.001",
            atlas_technique_name="Craft Adversarial Data: Black-Box Optimization",
            atlas_tactic="Evasion",
            description="Word-level adversarial text attack using synonym substitution.",
        )
        class TextFoolerAttack(BaseAttack):
            ...
    """

    def decorator(cls: type[BaseAttack]) -> type[BaseAttack]:
        cls.name = name
        cls.display_name = display_name
        cls.category = category
        cls.atlas_id = atlas_id
        cls.atlas_technique_name = atlas_technique_name
        cls.atlas_tactic = atlas_tactic
        cls.description = description
        cls.interface = interface

        if name in _ATTACK_REGISTRY:
            logger.warning(f"Attack '{name}' already registered. Overwriting.")
        _ATTACK_REGISTRY[name] = cls
        logger.debug(f"Registered attack: {name} ({category.value})")
        return cls

    return decorator


def get_registered_attacks() -> dict[str, type[BaseAttack]]:
    """Return all registered attack classes."""
    return _ATTACK_REGISTRY.copy()

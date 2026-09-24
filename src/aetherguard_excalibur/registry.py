"""Attack registry — discovers, loads, and manages attack plugins."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Any

from aetherguard_excalibur.attacks.base import (
    AttackParams,
    BaseAttack,
    get_registered_attacks,
)
from aetherguard_excalibur.models import AttackCategory, AttackMetadata

logger = logging.getLogger(__name__)


class AttackNotFoundError(Exception):
    """Raised when an attack name is not found in the registry."""

    pass


class AttackRegistry:
    """Manages discovery and instantiation of attack plugins.

    Automatically discovers all attack classes decorated with @register_attack
    by importing all subpackages of aetherguard_excalibur.attacks.
    """

    def __init__(self) -> None:
        self._attacks: dict[str, type[BaseAttack]] = {}
        self._discovered = False

    def discover_attacks(self) -> None:
        """Auto-discover all attack plugins from attacks/ subpackages.

        Imports every module in aetherguard_excalibur.attacks.* recursively,
        which triggers @register_attack decorators.
        """
        if self._discovered:
            return

        import aetherguard_excalibur.attacks as attacks_pkg

        for _importer, modname, _ispkg in pkgutil.walk_packages(
            attacks_pkg.__path__,
            prefix="aetherguard_excalibur.attacks.",
        ):
            try:
                importlib.import_module(modname)
                logger.debug(f"Loaded attack module: {modname}")
            except ImportError as e:
                # Optional dependencies might not be installed
                logger.debug(f"Skipped attack module {modname}: {e}")
            except Exception as e:
                logger.warning(f"Error loading attack module {modname}: {e}")

        self._attacks = get_registered_attacks()
        self._discovered = True
        logger.info(f"Discovered {len(self._attacks)} attack types")

    def register(self, attack_class: type[BaseAttack]) -> None:
        """Manually register an attack class."""
        name = attack_class.name
        if not name:
            raise ValueError("Attack class must have a 'name' attribute")
        self._attacks[name] = attack_class
        logger.debug(f"Manually registered attack: {name}")

    def get_attack(self, name: str) -> BaseAttack:
        """Get an attack instance by name.

        Args:
            name: Attack identifier (e.g., 'textfooler', 'pgd', 'maic')

        Returns:
            Instantiated attack object ready for setup().

        Raises:
            AttackNotFoundError: If attack name not found in registry.
        """
        if not self._discovered:
            self.discover_attacks()

        if name not in self._attacks:
            available = ", ".join(sorted(self._attacks.keys()))
            raise AttackNotFoundError(
                f"Attack '{name}' not found. Available: {available}"
            )

        attack_class = self._attacks[name]
        return attack_class()

    def list_attacks(self, category: str | None = None) -> list[AttackMetadata]:
        """List registered attacks with metadata.

        Args:
            category: Filter by category (optional). None returns all.

        Returns:
            List of AttackMetadata objects.
        """
        if not self._discovered:
            self.discover_attacks()

        results = []
        for name, cls in sorted(self._attacks.items()):
            if category and cls.category.value != category:
                continue
            results.append(
                AttackMetadata(
                    name=cls.name,
                    display_name=cls.display_name,
                    category=cls.category,
                    atlas_id=cls.atlas_id,
                    description=cls.description,
                    interface=cls.interface,
                    params_schema=cls.params_schema.model_json_schema() if cls.params_schema else {},
                )
            )
        return results

    def validate_params(self, name: str, params: dict[str, Any]) -> AttackParams:
        """Validate parameters against an attack's schema.

        Args:
            name: Attack name.
            params: Raw parameter dictionary.

        Returns:
            Validated AttackParams instance.
        """
        if not self._discovered:
            self.discover_attacks()

        if name not in self._attacks:
            raise AttackNotFoundError(f"Attack '{name}' not found")

        attack_class = self._attacks[name]
        return attack_class.params_schema(**params)

    @property
    def attack_count(self) -> int:
        """Number of registered attacks."""
        if not self._discovered:
            self.discover_attacks()
        return len(self._attacks)

    @property
    def categories(self) -> list[str]:
        """List of unique categories with registered attacks."""
        if not self._discovered:
            self.discover_attacks()
        cats = {cls.category.value for cls in self._attacks.values()}
        return sorted(cats)

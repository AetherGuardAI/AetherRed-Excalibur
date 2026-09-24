"""AetherGuard-Excalibur — AI Red-Teaming & Attack Simulation Platform.

Comprehensive adversarial testing for LLMs, AI agents, and RAG systems.
Surfaces vulnerabilities before real attackers do.

Usage:
    # CLI
    excalibur run textfooler -t openai
    excalibur campaign campaigns/quick_scan.yaml

    # Python API
    from aetherguard_excalibur import CampaignEngine, AttackRegistry
    from aetherguard_excalibur.config import load_campaign
"""

__version__ = "1.0.0"
__author__ = "AetherGuard AI"

from aetherguard_excalibur.engine import CampaignEngine
from aetherguard_excalibur.registry import AttackRegistry

__all__ = [
    "CampaignEngine",
    "AttackRegistry",
    "__version__",
]

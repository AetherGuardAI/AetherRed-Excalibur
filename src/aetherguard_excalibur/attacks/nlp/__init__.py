"""NLP & Language attacks — text-level adversarial manipulation."""

from aetherguard_excalibur.attacks.nlp.low_resource import LowResourceLanguageAttack
from aetherguard_excalibur.attacks.nlp.multi_turn_chain import MultiTurnChainAttack
from aetherguard_excalibur.attacks.nlp.textfooler import TextFoolerAttack

__all__ = ["LowResourceLanguageAttack", "MultiTurnChainAttack", "TextFoolerAttack"]

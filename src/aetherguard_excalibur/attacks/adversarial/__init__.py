"""Adversarial ML attacks — gradient-based perturbations and robustness testing."""

from aetherguard_excalibur.attacks.adversarial.fgsm import FGSMAttack
from aetherguard_excalibur.attacks.adversarial.pgd import PGDAttack
from aetherguard_excalibur.attacks.adversarial.randomized_smoothing import RandomizedSmoothingAttack
from aetherguard_excalibur.attacks.adversarial.transfer_attack import TransferAttack

__all__ = ["FGSMAttack", "PGDAttack", "RandomizedSmoothingAttack", "TransferAttack"]

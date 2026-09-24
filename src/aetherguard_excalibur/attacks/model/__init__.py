"""Model integrity attacks — watermark/backdoor auditing and hallucination induction."""

from aetherguard_excalibur.attacks.model.hallucination_induction import HallucinationInductionAttack
from aetherguard_excalibur.attacks.model.watermark_audit import WatermarkAuditAttack

__all__ = ["WatermarkAuditAttack", "HallucinationInductionAttack"]

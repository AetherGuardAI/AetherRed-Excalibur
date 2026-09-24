"""ART (Adversarial Robustness Toolbox) compatible metrics formatter."""

from __future__ import annotations

from aetherguard_excalibur.models import ARTMetrics, AttackResult, AttackStatus


class ARTFormatter:
    """Computes ART-compatible metrics from attack results.

    Metrics per attack category:
    - Precision: How many detected attacks were actual attacks
    - Recall: How many actual attacks were detected/blocked by the target
    - F1: Harmonic mean of precision and recall

    In our context:
    - "Attack success" = the target was vulnerable (attack bypassed defenses)
    - "Defense success" = the target blocked/detected the attack
    - Precision = defense_correct / (defense_correct + defense_false_alarm)
    - Recall = defense_correct / (defense_correct + attack_succeeded)
    """

    def compute(self, results: list[AttackResult]) -> ARTMetrics:
        """Compute ART-compatible metrics from results.

        The resilience perspective:
        - Higher recall = target blocks more attacks = more resilient
        - Higher precision = fewer false alarms

        Args:
            results: List of completed attack results.

        Returns:
            ARTMetrics with overall and per-category scores.
        """
        valid_results = [
            r for r in results
            if r.status in (AttackStatus.SUCCESS, AttackStatus.FAILURE)
        ]

        if not valid_results:
            return ARTMetrics()

        # Overall metrics
        total_payloads = sum(r.payloads_used for r in valid_results)
        total_blocked = total_payloads - sum(r.payloads_successful for r in valid_results)
        total_succeeded = sum(r.payloads_successful for r in valid_results)

        # Defense recall: what fraction of attacks did the target block?
        recall = total_blocked / total_payloads if total_payloads > 0 else 1.0
        # Defense precision: approximate (we don't have false alarm data from attacks alone)
        # Use 1.0 as default since we can't measure false positives from attack-only data
        precision = 1.0 if total_blocked > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # Per-category metrics
        per_category: dict[str, dict[str, float]] = {}
        category_groups: dict[str, list[AttackResult]] = {}
        for r in valid_results:
            cat = r.category.value if r.category else "unknown"
            category_groups.setdefault(cat, []).append(r)

        for cat, cat_results in category_groups.items():
            cat_payloads = sum(r.payloads_used for r in cat_results)
            cat_succeeded = sum(r.payloads_successful for r in cat_results)
            cat_blocked = cat_payloads - cat_succeeded

            cat_recall = cat_blocked / cat_payloads if cat_payloads > 0 else 1.0
            cat_precision = 1.0 if cat_blocked > 0 else 0.0
            cat_f1 = (
                (2 * cat_precision * cat_recall / (cat_precision + cat_recall))
                if (cat_precision + cat_recall) > 0
                else 0.0
            )

            per_category[cat] = {
                "precision": round(cat_precision, 4),
                "recall": round(cat_recall, 4),
                "f1_score": round(cat_f1, 4),
                "total_payloads": cat_payloads,
                "blocked": cat_blocked,
                "succeeded": cat_succeeded,
            }

        return ARTMetrics(
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            per_category=per_category,
        )

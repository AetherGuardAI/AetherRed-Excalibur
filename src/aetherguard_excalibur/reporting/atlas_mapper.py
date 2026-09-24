"""MITRE ATLAS technique mapping for attack results."""

from __future__ import annotations

from aetherguard_excalibur.models import AttackResult, AtlasMapping

# Comprehensive ATLAS technique mapping
ATLAS_MAPPING: dict[str, dict[str, str]] = {
    "pgd": {
        "technique_id": "AML.T0043",
        "technique_name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
    },
    "fgsm": {
        "technique_id": "AML.T0043",
        "technique_name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
    },
    "randomized_smoothing": {
        "technique_id": "AML.T0043.002",
        "technique_name": "Craft Adversarial Data: White-Box Optimization",
        "tactic": "ML Attack Staging",
    },
    "transfer_attack": {
        "technique_id": "AML.T0044",
        "technique_name": "Full ML Model Access",
        "tactic": "ML Attack Staging",
    },
    "textfooler": {
        "technique_id": "AML.T0043.001",
        "technique_name": "Craft Adversarial Data: Black-Box Optimization",
        "tactic": "ML Attack Staging",
    },
    "low_resource_language": {
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "tactic": "Initial Access",
    },
    "multi_turn_chain": {
        "technique_id": "AML.T0051.001",
        "technique_name": "Direct LLM Prompt Injection",
        "tactic": "Initial Access",
    },
    "evasion_benchmark": {
        "technique_id": "AML.T0015",
        "technique_name": "Evade ML Model",
        "tactic": "Defense Evasion",
    },
    "watermark_audit": {
        "technique_id": "AML.T0020",
        "technique_name": "Poison Training Data",
        "tactic": "ML Attack Staging",
    },
    "maic": {
        "technique_id": "AML.T0052",
        "technique_name": "Phishing via AI",
        "tactic": "Initial Access",
    },
    "cross_trust": {
        "technique_id": "AML.T0024",
        "technique_name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
    },
    "api_key_impersonation": {
        "technique_id": "AML.T0040",
        "technique_name": "ML Model Inference API Access",
        "tactic": "Initial Access",
    },
    "kb_poisoning": {
        "technique_id": "AML.T0020",
        "technique_name": "Poison Training Data",
        "tactic": "ML Attack Staging",
    },
    "embedding_inversion": {
        "technique_id": "AML.T0024",
        "technique_name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
    },
    "doc_injection": {
        "technique_id": "AML.T0020.001",
        "technique_name": "Inject Payload",
        "tactic": "ML Attack Staging",
    },
    "cross_contamination": {
        "technique_id": "AML.T0024",
        "technique_name": "Exfiltration via ML Inference API",
        "tactic": "Collection",
    },
    "hallucination_induction": {
        "technique_id": "AML.T0048",
        "technique_name": "Denial of ML Service",
        "tactic": "Impact",
    },
}


class AtlasMapper:
    """Maps attack results to MITRE ATLAS techniques."""

    def map_attack(self, attack_name: str, result: AttackResult) -> AtlasMapping:
        """Map a single attack result to its ATLAS technique.

        Args:
            attack_name: Attack identifier.
            result: Attack execution result.

        Returns:
            AtlasMapping with technique details.
        """
        mapping_data = ATLAS_MAPPING.get(attack_name, {
            "technique_id": "AML.T0000",
            "technique_name": "Unknown Technique",
            "tactic": "Unknown",
        })

        return AtlasMapping(
            technique_id=mapping_data["technique_id"],
            technique_name=mapping_data["technique_name"],
            tactic=mapping_data["tactic"],
            confidence=result.confidence if result.confidence > 0 else 1.0,
        )

    def map_all(self, results: list[AttackResult]) -> list[AtlasMapping]:
        """Map all attack results to ATLAS techniques.

        Args:
            results: List of attack results.

        Returns:
            List of AtlasMapping objects.
        """
        mappings = []
        for result in results:
            mapping = self.map_attack(result.attack_name, result)
            mappings.append(mapping)
        return mappings

    def generate_ttp_chain(self, results: list[AttackResult]) -> list[dict[str, str]]:
        """Generate a TTP (Tactics, Techniques, Procedures) kill chain.

        Args:
            results: Ordered list of attack results.

        Returns:
            List of TTP entries in kill chain order.
        """
        tactic_order = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "ML Model Access",
            "ML Attack Staging",
            "Defense Evasion",
            "Exfiltration",
            "Collection",
            "Impact",
        ]

        chain = []
        for result in results:
            if result.success_rate > 0:
                mapping = self.map_attack(result.attack_name, result)
                chain.append({
                    "tactic": mapping.tactic,
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name,
                    "attack": result.attack_name,
                    "success_rate": f"{result.success_rate:.0%}",
                })

        # Sort by tactic order
        chain.sort(key=lambda x: tactic_order.index(x["tactic"]) if x["tactic"] in tactic_order else 99)
        return chain

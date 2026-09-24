"""RAG & Embedding attacks — knowledge base poisoning, embedding inversion, and document injection."""

from aetherguard_excalibur.attacks.rag.doc_injection import DocInjectionAttack
from aetherguard_excalibur.attacks.rag.embedding_inversion import EmbeddingInversionAttack
from aetherguard_excalibur.attacks.rag.kb_poisoning import KBPoisoningAttack

__all__ = ["KBPoisoningAttack", "EmbeddingInversionAttack", "DocInjectionAttack"]

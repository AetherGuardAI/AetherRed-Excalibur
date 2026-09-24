"""Adapter factory — creates appropriate adapters based on configuration."""

from __future__ import annotations

from aetherguard_excalibur.adapters.base import ModelAdapter, TargetAdapter, VectorStoreAdapter
from aetherguard_excalibur.config import ModelConfig, TargetConfig, VectorStoreConfig


class AdapterFactory:
    """Factory for creating target, vector store, and model adapters."""

    def create_target(self, config: TargetConfig) -> TargetAdapter:
        """Create LLM target adapter based on configuration type.

        Args:
            config: Target configuration with type field.

        Returns:
            Appropriate TargetAdapter implementation.

        Raises:
            ValueError: If target type is not supported.
        """
        target_type = config.type.lower()

        if target_type == "openai":
            from aetherguard_excalibur.adapters.openai_adapter import OpenAIAdapter

            return OpenAIAdapter(config)
        elif target_type == "anthropic":
            from aetherguard_excalibur.adapters.anthropic_adapter import AnthropicAdapter

            return AnthropicAdapter(config)
        elif target_type == "azure":
            from aetherguard_excalibur.adapters.azure_adapter import AzureOpenAIAdapter

            return AzureOpenAIAdapter(config)
        elif target_type == "bedrock":
            from aetherguard_excalibur.adapters.bedrock_adapter import BedrockAdapter

            return BedrockAdapter(config)
        elif target_type in ("local", "vllm", "tgi", "ollama", "llamacpp"):
            from aetherguard_excalibur.adapters.local_adapter import LocalModelAdapter

            return LocalModelAdapter(config)
        else:
            raise ValueError(
                f"Unsupported target type: '{target_type}'. "
                f"Supported: openai, anthropic, azure, bedrock, local"
            )

    def create_vector_store(self, config: VectorStoreConfig) -> VectorStoreAdapter:
        """Create vector store adapter based on configuration type.

        Args:
            config: Vector store configuration.

        Returns:
            Appropriate VectorStoreAdapter implementation.

        Raises:
            ValueError: If vector store type is not supported.
            ImportError: If required client library is not installed.
        """
        store_type = config.type.lower()

        if store_type == "pinecone":
            from aetherguard_excalibur.adapters.vectorstore.pinecone_adapter import (
                PineconeVectorAdapter,
            )

            return PineconeVectorAdapter(config)
        elif store_type == "weaviate":
            from aetherguard_excalibur.adapters.vectorstore.weaviate_adapter import (
                WeaviateVectorAdapter,
            )

            return WeaviateVectorAdapter(config)
        elif store_type == "chroma":
            from aetherguard_excalibur.adapters.vectorstore.chroma_adapter import (
                ChromaVectorAdapter,
            )

            return ChromaVectorAdapter(config)
        elif store_type == "pgvector":
            from aetherguard_excalibur.adapters.vectorstore.pgvector_adapter import (
                PgvectorAdapter,
            )

            return PgvectorAdapter(config)
        else:
            raise ValueError(
                f"Unsupported vector store type: '{store_type}'. "
                f"Supported: pinecone, weaviate, chroma, pgvector"
            )

    def create_model_adapter(self, config: ModelConfig) -> ModelAdapter:
        """Create model adapter for direct white-box access.

        Args:
            config: Model configuration (framework, path, device).

        Returns:
            Appropriate ModelAdapter implementation.

        Raises:
            ValueError: If framework is not supported.
            ImportError: If required ML library is not installed.
        """
        framework = config.framework.lower()

        if framework in ("pytorch", "transformers", "huggingface"):
            from aetherguard_excalibur.adapters.model_adapter import (
                PyTorchModelAdapter,
            )

            return PyTorchModelAdapter(config)
        elif framework == "onnx":
            from aetherguard_excalibur.adapters.model_adapter import (
                ONNXModelAdapter,
            )

            return ONNXModelAdapter(config)
        else:
            raise ValueError(
                f"Unsupported model framework: '{framework}'. "
                f"Supported: pytorch, transformers, onnx"
            )

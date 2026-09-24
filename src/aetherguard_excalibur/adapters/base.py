"""Abstract base classes for target system adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single message in a chat conversation."""

    role: str = Field(description="Message role: system, user, assistant, tool")
    content: str = Field(description="Message content")
    name: str | None = Field(default=None, description="Optional name for multi-agent")


class ChatResponse(BaseModel):
    """Response from a chat completion call."""

    content: str = Field(description="Response text")
    model: str = Field(default="", description="Model that generated response")
    finish_reason: str = Field(default="stop", description="Why generation stopped")
    usage: dict[str, int] = Field(default_factory=dict, description="Token usage")
    raw: dict[str, Any] = Field(default_factory=dict, description="Raw provider response")


class QueryResult(BaseModel):
    """A single result from a vector store query."""

    id: str = Field(description="Document ID")
    score: float = Field(description="Similarity score")
    text: str = Field(default="", description="Document text content")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Document metadata")


class TargetAdapter(ABC):
    """Abstract base for LLM API target adapters (black-box interface).

    All black-box attacks interact with targets through this interface.
    """

    @abstractmethod
    async def chat(self, messages: list[ChatMessage], **kwargs: Any) -> ChatResponse:
        """Send a chat completion request to the target.

        Args:
            messages: Conversation messages.
            **kwargs: Provider-specific options (temperature, max_tokens, etc.)

        Returns:
            ChatResponse with model output.
        """
        ...

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings for a list of texts.

        Args:
            texts: List of strings to embed.

        Returns:
            List of embedding vectors.
        """
        ...

    async def complete(self, prompt: str, **kwargs: Any) -> str:
        """Simple text completion (convenience wrapper around chat).

        Args:
            prompt: Input prompt.
            **kwargs: Additional options.

        Returns:
            Generated text string.
        """
        messages = [ChatMessage(role="user", content=prompt)]
        response = await self.chat(messages, **kwargs)
        return response.content

    @abstractmethod
    async def close(self) -> None:
        """Close connections and clean up resources."""
        ...


class VectorStoreAdapter(ABC):
    """Abstract base for vector store adapters (RAG attack interface).

    Used by RAG/embedding attacks to interact with vector databases.
    """

    @abstractmethod
    async def insert(
        self,
        texts: list[str],
        embeddings: list[list[float]],
        metadata: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> list[str]:
        """Insert documents with pre-computed embeddings.

        Args:
            texts: Document texts.
            embeddings: Pre-computed embedding vectors.
            metadata: Optional metadata per document.
            ids: Optional explicit IDs.

        Returns:
            List of document IDs.
        """
        ...

    @abstractmethod
    async def query(
        self,
        embedding: list[float],
        top_k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[QueryResult]:
        """Query nearest neighbors by embedding vector.

        Args:
            embedding: Query vector.
            top_k: Number of results.
            filter: Optional metadata filter.

        Returns:
            List of QueryResult objects ordered by similarity.
        """
        ...

    @abstractmethod
    async def delete(self, ids: list[str]) -> int:
        """Delete documents by ID.

        Args:
            ids: Document IDs to delete.

        Returns:
            Number of documents deleted.
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close connections and clean up."""
        ...


class ModelAdapter(ABC):
    """Abstract base for direct model access (white-box interface).

    Used by gradient-based attacks (PGD, FGSM) and model inspection attacks
    that need direct access to model weights and gradients.
    """

    @abstractmethod
    def load_model(self, model_path: str, device: str = "cpu") -> Any:
        """Load model weights for white-box access.

        Args:
            model_path: Path to model weights or HuggingFace model ID.
            device: Target device (cpu, cuda, cuda:0).

        Returns:
            Loaded model object (framework-specific).
        """
        ...

    @abstractmethod
    def get_embeddings(self, model: Any, input_ids: Any) -> Any:
        """Get token embeddings from model.

        Args:
            model: Loaded model object.
            input_ids: Tokenized input tensor.

        Returns:
            Embedding tensor.
        """
        ...

    @abstractmethod
    def compute_loss(self, model: Any, input_ids: Any, labels: Any) -> Any:
        """Compute loss for gradient computation.

        Args:
            model: Loaded model object.
            input_ids: Input tensor.
            labels: Target labels tensor.

        Returns:
            Loss tensor (with grad_fn for backprop).
        """
        ...

    @abstractmethod
    def tokenize(self, text: str) -> Any:
        """Tokenize text into model input format.

        Args:
            text: Input text.

        Returns:
            Tokenized tensor.
        """
        ...

    @abstractmethod
    def detokenize(self, token_ids: Any) -> str:
        """Convert token IDs back to text.

        Args:
            token_ids: Token ID tensor.

        Returns:
            Decoded text string.
        """
        ...

"""Anthropic API adapter."""

from __future__ import annotations

import os
from typing import Any

import httpx

from aetherguard_excalibur.adapters.base import (
    ChatMessage,
    ChatResponse,
    TargetAdapter,
)
from aetherguard_excalibur.config import TargetConfig


class AnthropicAdapter(TargetAdapter):
    """Adapter for Anthropic Messages API."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._base_url = config.base_url or "https://api.anthropic.com"
        api_key_env = config.api_key_env or "EXCALIBUR_ANTHROPIC_API_KEY"
        self._api_key = os.environ.get(api_key_env, "")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            timeout=config.timeout,
        )

    async def chat(self, messages: list[ChatMessage], **kwargs: Any) -> ChatResponse:
        """Send messages request to Anthropic."""
        # Separate system message from conversation
        system_msg = ""
        conversation = []
        for m in messages:
            if m.role == "system":
                system_msg = m.content
            else:
                conversation.append({"role": m.role, "content": m.content})

        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": conversation,
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
            "temperature": kwargs.get("temperature", self._config.temperature),
        }
        if system_msg:
            payload["system"] = system_msg

        response = await self._client.post("/v1/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        return ChatResponse(
            content=content,
            model=data.get("model", self._config.model),
            finish_reason=data.get("stop_reason", "end_turn"),
            usage=data.get("usage", {}),
            raw=data,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Anthropic does not have a public embeddings API. Raises NotImplementedError."""
        raise NotImplementedError(
            "Anthropic does not provide an embeddings API. "
            "Use a different target for embedding-based attacks."
        )

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()

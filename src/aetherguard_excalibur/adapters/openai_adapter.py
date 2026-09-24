"""OpenAI API adapter."""

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


class OpenAIAdapter(TargetAdapter):
    """Adapter for OpenAI-compatible chat/completions and embeddings API."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._base_url = config.base_url or "https://api.openai.com/v1"
        api_key_env = config.api_key_env or "EXCALIBUR_OPENAI_API_KEY"
        self._api_key = os.environ.get(api_key_env, "")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            timeout=config.timeout,
        )

    async def chat(self, messages: list[ChatMessage], **kwargs: Any) -> ChatResponse:
        """Send chat completion request to OpenAI."""
        payload = {
            "model": self._config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }

        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        return ChatResponse(
            content=choice["message"]["content"],
            model=data.get("model", self._config.model),
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
            raw=data,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings from OpenAI embeddings API."""
        payload = {
            "model": "text-embedding-3-small",
            "input": texts,
        }

        response = await self._client.post("/embeddings", json=payload)
        response.raise_for_status()
        data = response.json()

        return [item["embedding"] for item in data["data"]]

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()

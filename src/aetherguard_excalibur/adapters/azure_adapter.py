"""Azure OpenAI adapter."""

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


class AzureOpenAIAdapter(TargetAdapter):
    """Adapter for Azure OpenAI Service."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._base_url = config.base_url  # e.g., https://<resource>.openai.azure.com
        if not self._base_url:
            raise ValueError("Azure OpenAI requires base_url (resource endpoint)")

        api_key_env = config.api_key_env or "EXCALIBUR_AZURE_OPENAI_API_KEY"
        self._api_key = os.environ.get(api_key_env, "")
        self._api_version = "2024-02-01"
        self._deployment = config.model  # Azure uses deployment name

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "api-key": self._api_key,
                "Content-Type": "application/json",
            },
            timeout=config.timeout,
        )

    async def chat(self, messages: list[ChatMessage], **kwargs: Any) -> ChatResponse:
        """Send chat completion to Azure OpenAI deployment."""
        url = (
            f"/openai/deployments/{self._deployment}/chat/completions"
            f"?api-version={self._api_version}"
        )
        payload = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }

        response = await self._client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        return ChatResponse(
            content=choice["message"]["content"],
            model=data.get("model", self._deployment),
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
            raw=data,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings from Azure OpenAI embeddings deployment."""
        url = (
            f"/openai/deployments/{self._deployment}/embeddings"
            f"?api-version={self._api_version}"
        )
        payload = {"input": texts}

        response = await self._client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

        return [item["embedding"] for item in data["data"]]

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()

"""AWS Bedrock adapter."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from aetherguard_excalibur.adapters.base import (
    ChatMessage,
    ChatResponse,
    TargetAdapter,
)
from aetherguard_excalibur.config import TargetConfig


class BedrockAdapter(TargetAdapter):
    """Adapter for AWS Bedrock Converse API.

    Uses the Bedrock runtime converse endpoint for model-agnostic invocation.
    Requires AWS credentials configured via environment (AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) or IAM role.
    """

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._region = config.region or os.environ.get("AWS_REGION", "us-east-1")
        self._model_id = config.model  # e.g., anthropic.claude-3-sonnet-20240229-v1:0
        self._client: Any = None

    async def _get_client(self) -> Any:
        """Lazy-init boto3 bedrock-runtime client."""
        if self._client is None:
            try:
                import boto3

                self._client = boto3.client(
                    "bedrock-runtime", region_name=self._region
                )
            except ImportError:
                raise ImportError(
                    "boto3 is required for Bedrock adapter. Install with: pip install boto3"
                )
        return self._client

    async def chat(self, messages: list[ChatMessage], **kwargs: Any) -> ChatResponse:
        """Send converse request to Bedrock."""
        client = await self._get_client()

        # Convert to Bedrock converse format
        system_msgs = []
        conversation = []
        for m in messages:
            if m.role == "system":
                system_msgs.append({"text": m.content})
            else:
                conversation.append({
                    "role": m.role,
                    "content": [{"text": m.content}],
                })

        params: dict[str, Any] = {
            "modelId": self._model_id,
            "messages": conversation,
            "inferenceConfig": {
                "maxTokens": kwargs.get("max_tokens", self._config.max_tokens),
                "temperature": kwargs.get("temperature", self._config.temperature),
            },
        }
        if system_msgs:
            params["system"] = system_msgs

        response = client.converse(**params)

        content = ""
        for block in response.get("output", {}).get("message", {}).get("content", []):
            if "text" in block:
                content += block["text"]

        return ChatResponse(
            content=content,
            model=self._model_id,
            finish_reason=response.get("stopReason", "end_turn"),
            usage=response.get("usage", {}),
            raw=response,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings from Bedrock (Titan Embeddings or Cohere)."""
        client = await self._get_client()
        embeddings = []

        for text in texts:
            body = json.dumps({"inputText": text})
            response = client.invoke_model(
                modelId="amazon.titan-embed-text-v2:0",
                body=body,
                contentType="application/json",
            )
            result = json.loads(response["body"].read())
            embeddings.append(result["embedding"])

        return embeddings

    async def close(self) -> None:
        """Close Bedrock client."""
        self._client = None

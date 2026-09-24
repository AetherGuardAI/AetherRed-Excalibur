"""Model adapters for direct white-box access (PyTorch/HuggingFace/ONNX)."""

from __future__ import annotations

import logging
from typing import Any

from aetherguard_excalibur.adapters.base import ModelAdapter
from aetherguard_excalibur.config import ModelConfig

logger = logging.getLogger(__name__)


class PyTorchModelAdapter(ModelAdapter):
    """White-box adapter for PyTorch/HuggingFace Transformers models.

    Provides direct access to model weights, gradients, and embeddings
    for gradient-based attacks (PGD, FGSM) and model inspection.
    """

    def __init__(self, config: ModelConfig) -> None:
        self._config = config
        self._model: Any = None
        self._tokenizer: Any = None

    def load_model(self, model_path: str, device: str = "cpu") -> Any:
        """Load a HuggingFace model with gradient support.

        Args:
            model_path: HuggingFace model ID or local path.
            device: Target device (cpu, cuda, cuda:0).

        Returns:
            Loaded PyTorch model in eval mode.
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError:
            raise ImportError(
                "PyTorch and transformers required. Install with: "
                "pip install 'aetherguard-excalibur[whitebox]'"
            )

        device = device or self._config.device
        dtype_map = {
            "float32": torch.float32,
            "float16": torch.float16,
            "bfloat16": torch.bfloat16,
        }
        dtype = dtype_map.get(self._config.dtype, torch.float32)

        logger.info(f"Loading model: {model_path} on {device} ({self._config.dtype})")

        self._tokenizer = AutoTokenizer.from_pretrained(model_path)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=dtype,
            device_map=device if device != "cpu" else None,
        )

        if device == "cpu" or not self._model.device:
            self._model = self._model.to(device)

        self._model.eval()
        return self._model

    def get_embeddings(self, model: Any, input_ids: Any) -> Any:
        """Get token embeddings from model's embedding layer.

        Args:
            model: Loaded PyTorch model.
            input_ids: Tokenized input tensor [batch, seq_len].

        Returns:
            Embedding tensor [batch, seq_len, hidden_dim].
        """
        import torch

        embedding_layer = model.get_input_embeddings()
        with torch.no_grad():
            embeddings = embedding_layer(input_ids)
        return embeddings

    def get_embeddings_with_grad(self, model: Any, input_ids: Any) -> Any:
        """Get token embeddings with gradient tracking enabled.

        Used by PGD/FGSM to compute gradients w.r.t. input embeddings.

        Args:
            model: Loaded PyTorch model.
            input_ids: Tokenized input tensor.

        Returns:
            Embedding tensor with requires_grad=True.
        """
        embedding_layer = model.get_input_embeddings()
        embeddings = embedding_layer(input_ids)
        embeddings.requires_grad_(True)
        return embeddings

    def compute_loss(self, model: Any, input_ids: Any, labels: Any) -> Any:
        """Compute cross-entropy loss for gradient computation.

        Args:
            model: Loaded PyTorch model.
            input_ids: Input tensor.
            labels: Target label tensor (shifted input_ids for causal LM).

        Returns:
            Loss tensor with grad_fn for backpropagation.
        """
        outputs = model(input_ids=input_ids, labels=labels)
        return outputs.loss

    def forward_with_embeddings(self, model: Any, embeddings: Any, attention_mask: Any = None) -> Any:
        """Forward pass using embeddings directly (bypass embedding layer).

        Used by PGD/FGSM to propagate perturbed embeddings through the model.

        Args:
            model: Loaded PyTorch model.
            embeddings: Input embeddings tensor [batch, seq_len, hidden_dim].
            attention_mask: Optional attention mask.

        Returns:
            Model output logits.
        """
        outputs = model(inputs_embeds=embeddings, attention_mask=attention_mask)
        return outputs.logits

    def tokenize(self, text: str) -> Any:
        """Tokenize text into model input format.

        Args:
            text: Input text string.

        Returns:
            Dictionary with input_ids, attention_mask as tensors.
        """
        if self._tokenizer is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        return self._tokenizer(text, return_tensors="pt", padding=True, truncation=True)

    def detokenize(self, token_ids: Any) -> str:
        """Convert token IDs back to text.

        Args:
            token_ids: Token ID tensor or list.

        Returns:
            Decoded text string.
        """
        if self._tokenizer is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        return self._tokenizer.decode(token_ids, skip_special_tokens=True)


class ONNXModelAdapter(ModelAdapter):
    """White-box adapter for ONNX Runtime models.

    Provides inference access for ONNX-exported models.
    Gradient computation uses finite differences (numerical approximation)
    since ONNX Runtime doesn't support backpropagation.
    """

    def __init__(self, config: ModelConfig) -> None:
        self._config = config
        self._session: Any = None
        self._tokenizer: Any = None

    def load_model(self, model_path: str, device: str = "cpu") -> Any:
        """Load an ONNX model for inference.

        Args:
            model_path: Path to .onnx file.
            device: Device hint (onnxruntime handles via providers).

        Returns:
            ONNX InferenceSession.
        """
        try:
            import onnxruntime as ort
        except ImportError:
            raise ImportError(
                "onnxruntime required. Install with: "
                "pip install 'aetherguard-excalibur[whitebox]'"
            )

        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"] if "cuda" in device else ["CPUExecutionProvider"]
        self._session = ort.InferenceSession(model_path, providers=providers)

        logger.info(f"Loaded ONNX model: {model_path} (providers={providers})")
        return self._session

    def get_embeddings(self, model: Any, input_ids: Any) -> Any:
        """Get embeddings via ONNX inference (output from embedding layer).

        Note: Requires model exported with intermediate outputs or
        a separate embedding-only ONNX graph.
        """
        import numpy as np

        if hasattr(input_ids, "numpy"):
            input_ids = input_ids.numpy()

        # Run inference to get hidden states
        inputs = {"input_ids": input_ids.astype(np.int64)}
        outputs = model.run(None, inputs)
        return outputs[0]  # Assumes first output is hidden states

    def compute_loss(self, model: Any, input_ids: Any, labels: Any) -> Any:
        """Compute loss via ONNX (forward pass only, no gradient).

        For ONNX, gradient computation is done via finite differences
        in the attack implementations.
        """
        import numpy as np

        if hasattr(input_ids, "numpy"):
            input_ids = input_ids.numpy()

        inputs = {"input_ids": input_ids.astype(np.int64)}
        outputs = model.run(None, inputs)
        logits = outputs[0]

        # Compute cross-entropy manually
        from scipy.special import log_softmax

        log_probs = log_softmax(logits, axis=-1)
        if hasattr(labels, "numpy"):
            labels = labels.numpy()
        loss = -np.mean(log_probs[np.arange(labels.shape[0]), :, labels.flatten()])
        return loss

    def tokenize(self, text: str) -> Any:
        """Tokenize text (requires separate tokenizer loading)."""
        if self._tokenizer is None:
            try:
                from transformers import AutoTokenizer

                # Attempt to infer tokenizer from model path
                self._tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
            except ImportError:
                raise ImportError("transformers required for ONNX tokenization")
        return self._tokenizer(text, return_tensors="np", padding=True, truncation=True)

    def detokenize(self, token_ids: Any) -> str:
        """Convert token IDs back to text."""
        if self._tokenizer is None:
            raise RuntimeError("Tokenizer not available")
        return self._tokenizer.decode(token_ids, skip_special_tokens=True)

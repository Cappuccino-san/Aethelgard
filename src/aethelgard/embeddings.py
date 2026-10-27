"""Subsystem Layer 5: Semantic Embedding Engine (nomic-embed-text via Ollama + Deterministic Mock).

Generates 768-dimensional normalized dense vectors for sqlite-vec (vec0).
When Ollama is running and has `nomic-embed-text`, it invokes local inference.
When Ollama is unreachable or offline, it transparently falls back to a deterministic,
unit-normalized BLAKE3 token-aware embedding generator so the system remains fully functional offline.
"""

import json
import math
import os
import re
import struct
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from blake3 import blake3

DEFAULT_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = "nomic-embed-text"
EMBEDDING_DIM = 768
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def generate_mock_embedding(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """Generate a deterministic, semantic-aware, unit-normalized float vector of length `dim` using BLAKE3."""
    vec = [0.0] * dim

    # 1. Whole text component (exact match bias)
    h_full = blake3(b"full:" + text.strip().lower().encode("utf-8")).digest(length=dim * 4)
    ints_full = struct.unpack(f"<{dim}i", h_full)
    norm_full = math.sqrt(sum(x * x for x in ints_full)) or 1.0
    for i, x in enumerate(ints_full):
        vec[i] += (x / norm_full) * 1.0

    # 2. Token components (bag-of-words semantic similarity)
    tokens = TOKEN_RE.findall(text.lower())
    if tokens:
        for tok in set(tokens):
            h_tok = blake3(b"tok:" + tok.encode("utf-8")).digest(length=dim * 4)
            ints_tok = struct.unpack(f"<{dim}i", h_tok)
            norm_tok = math.sqrt(sum(x * x for x in ints_tok)) or 1.0
            for i, x in enumerate(ints_tok):
                vec[i] += (x / norm_tok) * 1.5

    # Normalize final vector to unit norm (L2 = 1.0)
    final_norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / final_norm for x in vec]


class OllamaEmbeddingClient:
    """Client for fetching embeddings from Ollama with transparent fallback to deterministic mock."""

    def __init__(
        self,
        host: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        timeout: float = 0.5,
        cooldown_seconds: float = 10.0,
    ) -> None:
        self.host = (host or DEFAULT_OLLAMA_HOST).rstrip("/")
        self.model = model
        self.timeout = timeout
        self.cooldown_seconds = cooldown_seconds
        self._is_available: Optional[bool] = None
        self._last_check_timestamp: float = 0.0

    def is_available(self) -> bool:
        """Check if Ollama server is reachable and responsive."""
        if os.environ.get("AETHELGARD_FORCE_MOCK_EMBEDDINGS") in ("1", "true", "TRUE"):
            return False

        now = time.time()
        if self._is_available is False and (now - self._last_check_timestamp < self.cooldown_seconds):
            return False

        try:
            req = urllib.request.Request(
                f"{self.host}/api/tags",
                headers={"User-Agent": "Aethelgard-Client/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    self._is_available = True
                    self._last_check_timestamp = now
                    return True
        except Exception:
            pass

        self._is_available = False
        self._last_check_timestamp = now
        return False

    def embed(self, text: str) -> list[float]:
        """Fetch 768d embedding for `text`, falling back to deterministic mock if unavailable."""
        if not self.is_available():
            return generate_mock_embedding(text, dim=EMBEDDING_DIM)

        # 1. Attempt Ollama /api/embeddings (classic)
        try:
            payload = json.dumps({"model": self.model, "prompt": text}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.host}/api/embeddings",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Aethelgard-Client/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    emb = data.get("embedding")
                    if isinstance(emb, list) and len(emb) == EMBEDDING_DIM:
                        return [float(x) for x in emb]
        except Exception:
            pass

        # 2. Attempt Ollama /api/embed (modern)
        try:
            payload = json.dumps({"model": self.model, "input": text}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.host}/api/embed",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Aethelgard-Client/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    embeddings = data.get("embeddings")
                    if isinstance(embeddings, list) and len(embeddings) > 0:
                        emb = embeddings[0]
                        if isinstance(emb, list) and len(emb) == EMBEDDING_DIM:
                            return [float(x) for x in emb]
        except Exception:
            pass

        # Mark unavailable to prevent repeated timeouts
        self._is_available = False
        self._last_check_timestamp = time.time()
        return generate_mock_embedding(text, dim=EMBEDDING_DIM)


_DEFAULT_CLIENT: Optional[OllamaEmbeddingClient] = None


def get_embedding(
    text: str,
    host: Optional[str] = None,
    model: Optional[str] = None,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
) -> list[float]:
    """Retrieve 768d embedding using the injected embed_fn, Ollama, or deterministic fallback."""
    if embed_fn is not None:
        return embed_fn(text)

    global _DEFAULT_CLIENT
    if host is not None or model is not None:
        client = OllamaEmbeddingClient(host=host, model=model or DEFAULT_MODEL)
        return client.embed(text)

    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = OllamaEmbeddingClient()
    return _DEFAULT_CLIENT.embed(text)

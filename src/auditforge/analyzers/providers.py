"""Inference Provider Abstraction for AuditForge Semantic Analysis.

Supports:
1. Local Ollama runtime (default for local open-weight Qwen/Llama)
2. OpenAI-compatible endpoints (vLLM, TGI, LocalAI, external OpenAI-compatible proxies)
3. Disabled/Deterministic-only mode (guaranteed offline zero-external dependency)
"""

from abc import ABC, abstractmethod
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


class InferenceProvider(ABC):
    """Abstract interface for semantic inference providers."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the inference provider is reachable and active."""
        pass

    @abstractmethod
    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Optional[Dict[str, Any]] = None,
        timeout_seconds: float = 15.0,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Generate structured JSON response.

        Returns:
            Tuple of (parsed_json_dict_or_None, metadata_dict)
            metadata includes: latency_ms, provider, model, error
        """
        pass


class OllamaProvider(InferenceProvider):
    """Local Ollama open-weight inference provider."""

    def __init__(self, host: str = "http://localhost:11434", model: str = "qwen2.5:7b"):
        self.host = host.rstrip("/")
        self.model = model

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=1.5) as res:
                return res.status == 200
        except Exception:
            return False

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Optional[Dict[str, Any]] = None,
        timeout_seconds: float = 15.0,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        meta: Dict[str, Any] = {
            "provider": "ollama",
            "model": self.model,
            "latency_ms": 0.0,
            "error": None,
        }
        t0 = time.perf_counter()

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": 512,
                "num_ctx": 8192,
            },
        }

        try:
            body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=body_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_seconds) as res:
                raw_bytes = res.read(65536)
                meta["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                resp_json = json.loads(raw_bytes.decode("utf-8"))
                response_str = resp_json.get("response", "")
                parsed = json.loads(response_str)
                return parsed, meta
        except Exception as exc:
            meta["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            meta["error"] = str(exc)
            return None, meta


class OpenAICompatibleProvider(InferenceProvider):
    """OpenAI-compatible inference endpoint (e.g. vLLM, TGI, LocalAI)."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000/v1",
        model: str = "qwen2.5-7b",
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or "EMPTY"

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            with urllib.request.urlopen(req, timeout=1.5) as res:
                return res.status == 200
        except Exception:
            return False

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Optional[Dict[str, Any]] = None,
        timeout_seconds: float = 15.0,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        meta: Dict[str, Any] = {
            "provider": "openai_compatible",
            "model": self.model,
            "latency_ms": 0.0,
            "error": None,
        }
        t0 = time.perf_counter()

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 512,
            "response_format": {"type": "json_object"},
        }

        try:
            body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_seconds) as res:
                raw_bytes = res.read(65536)
                meta["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                resp_json = json.loads(raw_bytes.decode("utf-8"))
                choices = resp_json.get("choices", [])
                if not choices:
                    meta["error"] = "No completion choices returned"
                    return None, meta
                content_str = choices[0].get("message", {}).get("content", "")
                parsed = json.loads(content_str)
                return parsed, meta
        except Exception as exc:
            meta["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            meta["error"] = str(exc)
            return None, meta


class DisabledProvider(InferenceProvider):
    """Disabled / Offline inference provider ensuring purely deterministic execution."""

    def is_available(self) -> bool:
        return False

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Optional[Dict[str, Any]] = None,
        timeout_seconds: float = 15.0,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        return None, {
            "provider": "disabled",
            "model": "none",
            "latency_ms": 0.0,
            "error": "Inference disabled or unconfigured",
        }


def get_inference_provider(
    provider_type: Optional[str] = None,
    host_or_url: Optional[str] = None,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
) -> InferenceProvider:
    """Factory creating configured InferenceProvider instance."""
    p_type = (provider_type or "ollama").lower()
    if p_type == "disabled" or p_type == "none":
        return DisabledProvider()
    elif p_type in ("openai", "vllm", "openai_compatible"):
        return OpenAICompatibleProvider(
            base_url=host_or_url or "http://localhost:8000/v1",
            model=model_name or "qwen2.5-7b",
            api_key=api_key,
        )
    else:
        return OllamaProvider(
            host=host_or_url or "http://localhost:11434",
            model=model_name or "qwen2.5:7b",
        )

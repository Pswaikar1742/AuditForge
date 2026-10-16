"""Unit tests for inference provider abstraction."""

import json
from unittest.mock import MagicMock, patch
from auditforge.analyzers.providers import (
    DisabledProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    get_inference_provider,
)


def test_disabled_provider():
    p = DisabledProvider()
    assert p.is_available() is False
    res, meta = p.generate_json("sys", "user")
    assert res is None
    assert meta["provider"] == "disabled"
    assert "disabled" in meta["error"].lower()


def test_ollama_provider_mocked():
    p = OllamaProvider(host="http://localhost:11434", model="qwen2.5:7b")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps({
        "response": json.dumps({"is_suspicious": True, "confidence": 0.95})
    }).encode("utf-8")
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_cm):
        res, meta = p.generate_json("system", "prompt")
        assert res is not None
        assert res["is_suspicious"] is True
        assert meta["provider"] == "ollama"
        assert meta["latency_ms"] >= 0.0


def test_openai_compatible_provider_mocked():
    p = OpenAICompatibleProvider(base_url="http://localhost:8000/v1", model="qwen2.5-7b")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps({
        "choices": [
            {"message": {"content": json.dumps({"is_suspicious": False, "confidence": 0.1})}}
        ]
    }).encode("utf-8")
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_cm):
        res, meta = p.generate_json("system", "prompt")
        assert res is not None
        assert res["is_suspicious"] is False
        assert meta["provider"] == "openai_compatible"


def test_get_inference_provider_factory():
    p_off = get_inference_provider("disabled")
    assert isinstance(p_off, DisabledProvider)

    p_vllm = get_inference_provider("vllm", host_or_url="http://vllm:8000/v1")
    assert isinstance(p_vllm, OpenAICompatibleProvider)
    assert p_vllm.base_url == "http://vllm:8000/v1"

    p_ollama = get_inference_provider("ollama")
    assert isinstance(p_ollama, OllamaProvider)

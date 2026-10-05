"""
Unit tests — AI Provider abstraction + GeminiProvider.

No real GEMINI_API_KEY is used or fabricated anywhere in this file, per
explicit instruction. Real Gemini SDK calls are mocked; unconfigured /
error paths are tested for real (they don't need a key to prove the
code behaves correctly when one is absent or rejected).
"""
import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


def test_is_configured_false_without_key(monkeypatch):
    from app.services.v5.ai_provider_service import GeminiProvider
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "")
    provider = GeminiProvider()
    ok, msg = provider.is_configured()
    assert ok is False
    assert "GEMINI_API_KEY" in msg


def test_is_configured_true_with_key(monkeypatch):
    from app.services.v5.ai_provider_service import GeminiProvider
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "fake-test-key-not-real")
    monkeypatch.setattr("app.core.config.settings.AI_MODEL", "gemini-2.0-flash")
    provider = GeminiProvider()
    ok, msg = provider.is_configured()
    assert ok is True


def test_get_provider_returns_none_when_disabled(monkeypatch):
    from app.services.v5.ai_provider_service import get_provider
    monkeypatch.setattr("app.core.config.settings.AI_ENABLED", False)
    assert get_provider() is None


def test_get_provider_returns_gemini_when_enabled(monkeypatch):
    from app.services.v5.ai_provider_service import get_provider, GeminiProvider
    monkeypatch.setattr("app.core.config.settings.AI_ENABLED", True)
    monkeypatch.setattr("app.core.config.settings.AI_PROVIDER", "gemini")
    provider = get_provider()
    assert isinstance(provider, GeminiProvider)


def test_get_provider_unknown_provider_returns_none(monkeypatch):
    from app.services.v5.ai_provider_service import get_provider
    monkeypatch.setattr("app.core.config.settings.AI_ENABLED", True)
    monkeypatch.setattr("app.core.config.settings.AI_PROVIDER", "nonexistent_provider")
    assert get_provider() is None


def test_validate_ai_config_disabled(monkeypatch):
    from app.services.v5.ai_provider_service import validate_ai_config
    monkeypatch.setattr("app.core.config.settings.AI_ENABLED", False)
    result = validate_ai_config()
    assert result["enabled"] is False
    assert result["configured"] is False


def test_validate_ai_config_enabled_but_unconfigured(monkeypatch):
    from app.services.v5.ai_provider_service import validate_ai_config
    monkeypatch.setattr("app.core.config.settings.AI_ENABLED", True)
    monkeypatch.setattr("app.core.config.settings.AI_PROVIDER", "gemini")
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "")
    result = validate_ai_config()
    assert result["configured"] is False


@pytest.mark.asyncio
async def test_generate_raises_unavailable_without_key(monkeypatch):
    """Real behavior with no key — no mock needed, this IS the real code path."""
    from app.services.v5.ai_provider_service import GeminiProvider, AIProviderUnavailableError, AIRequest
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "")
    provider = GeminiProvider()
    request = AIRequest(task="test", system_instruction="test", untrusted_context="test")
    with pytest.raises(AIProviderUnavailableError):
        await provider.generate(request)


@pytest.mark.asyncio
async def test_health_check_unconfigured(monkeypatch):
    from app.services.v5.ai_provider_service import GeminiProvider
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "")
    provider = GeminiProvider()
    result = await provider.health_check()
    assert result["available"] is False


@pytest.mark.asyncio
async def test_generate_success_with_mocked_sdk(monkeypatch):
    """Mocked Gemini response — proves the success path parses correctly
    without a real API key or network call."""
    from app.services.v5.ai_provider_service import GeminiProvider, AIRequest
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "fake-test-key")
    monkeypatch.setattr("app.core.config.settings.AI_MODEL", "gemini-2.0-flash")

    provider = GeminiProvider()

    mock_response = MagicMock()
    mock_response.text = '{"summary": "test", "observed_evidence": [], "ai_inference": [], "confidence": "low", "severity": "info", "recommended_actions": []}'
    mock_response.usage_metadata = MagicMock(prompt_token_count=10, candidates_token_count=20)
    mock_response.candidates = [MagicMock(finish_reason="STOP")]

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    provider._client = mock_client

    request = AIRequest(task="test", system_instruction="test", untrusted_context="test",
                        response_schema={"type": "object"})
    response = await provider.generate(request)
    assert response.parsed["summary"] == "test"
    assert response.input_tokens == 10


@pytest.mark.asyncio
async def test_generate_malformed_json_raises(monkeypatch):
    """Mocked response that isn't valid JSON when a schema was requested."""
    from app.services.v5.ai_provider_service import GeminiProvider, AIRequest, AIProviderMalformedResponseError
    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "fake-test-key")
    monkeypatch.setattr("app.core.config.settings.AI_MODEL", "gemini-2.0-flash")

    provider = GeminiProvider()
    mock_response = MagicMock()
    mock_response.text = "not valid json {{{"
    mock_response.usage_metadata = None
    mock_response.candidates = []

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    provider._client = mock_client

    request = AIRequest(task="test", system_instruction="test", untrusted_context="test",
                        response_schema={"type": "object"})
    with pytest.raises(AIProviderMalformedResponseError):
        await provider.generate(request)


@pytest.mark.asyncio
async def test_generate_timeout(monkeypatch):
    """Mocked slow call — proves timeout handling without waiting on a real network call."""
    import asyncio
    from app.services.v5.ai_provider_service import GeminiProvider, AIRequest, AIProviderTimeoutError

    monkeypatch.setattr("app.core.config.settings.GEMINI_API_KEY", "fake-test-key")
    monkeypatch.setattr("app.core.config.settings.AI_MODEL", "gemini-2.0-flash")

    provider = GeminiProvider()
    provider._timeout = 0.05  # force a fast timeout for the test

    def slow_call(**kwargs):
        import time
        time.sleep(1)
        return MagicMock()

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = slow_call
    provider._client = mock_client

    request = AIRequest(task="test", system_instruction="test", untrusted_context="test")
    with pytest.raises(AIProviderTimeoutError):
        await provider.generate(request)

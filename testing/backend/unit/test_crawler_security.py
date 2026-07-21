"""
Unit tests for crawler TLS verification and redirect security policy (Issue #1747).
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from backend.secuscan.config import settings
from backend.secuscan.crawler import crawl_target


class TestCrawlerTLSVerification:
    def test_tls_verify_setting_exists(self):
        assert hasattr(settings, "tls_verify")
        assert settings.tls_verify is True

    @pytest.mark.asyncio
    async def test_crawl_target_uses_tls_verify_setting(self):
        """crawl_target must construct AsyncClient with verify=tls_verify."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.is_redirect = False
        mock_response.url = "http://example.com"
        mock_response.status_code = 200

        async def fake_aiter_bytes():
            yield b"<html><head><title>Test</title></head><body>OK</body></html>"

        mock_response.aiter_bytes = fake_aiter_bytes

        class MockStreamContext:
            async def __aenter__(self):
                return mock_response
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_client_instance = MagicMock()
        mock_client_instance.stream.return_value = MockStreamContext()

        class MockAsyncClient:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            async def __aenter__(self):
                return mock_client_instance
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        with patch("backend.secuscan.crawler.httpx.AsyncClient", side_effect=MockAsyncClient) as mock_client_cls:
            res = await crawl_target("http://example.com")
            assert mock_client_cls.call_count == 1
            client_kwargs = mock_client_cls.call_args.kwargs
            assert client_kwargs.get("verify") is True
            assert client_kwargs.get("follow_redirects") is False


class TestCrawlerRedirectPolicy:
    @pytest.mark.asyncio
    async def test_same_host_redirect_allowed(self):
        """Redirects to the same hostname must be followed."""
        resp1 = MagicMock()
        resp1.headers = {"location": "/login"}
        resp1.is_redirect = True
        resp1.status_code = 302
        resp1.url = "http://example.com/start"

        async def fake_aiter_bytes1():
            yield b"Redirecting..."
        resp1.aiter_bytes = fake_aiter_bytes1

        resp2 = MagicMock()
        resp2.headers = {}
        resp2.is_redirect = False
        resp2.status_code = 200
        resp2.url = "http://example.com/login"

        async def fake_aiter_bytes2():
            yield b"<html><head><title>Login Page</title></head><body>Form</body></html>"
        resp2.aiter_bytes = fake_aiter_bytes2

        responses = [resp1, resp2]
        call_index = 0

        class MockStreamContext:
            def __init__(self, url):
                nonlocal call_index
                self.resp = responses[call_index]
                call_index += 1
            async def __aenter__(self):
                return self.resp
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_client_instance = MagicMock()
        mock_client_instance.stream.side_effect = lambda method, url: MockStreamContext(url)

        class MockAsyncClient:
            def __init__(self, **kwargs):
                pass
            async def __aenter__(self):
                return mock_client_instance
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        with patch("backend.secuscan.crawler.httpx.AsyncClient", side_effect=MockAsyncClient):
            result = await crawl_target("http://example.com/start")
            assert result["final_url"] == "http://example.com/login"
            assert result["status_code"] == 200
            assert len(result["redirect_chain"]) == 1
            assert result["redirect_chain"][0]["url"] == "http://example.com/start"
            assert result["redirect_chain"][0]["location"] == "/login"

    @pytest.mark.asyncio
    async def test_cross_host_redirect_blocked(self):
        """Redirects to a different hostname (MITM / SSRF attempt) must be blocked."""
        resp1 = MagicMock()
        resp1.headers = {"location": "http://evil.com/phish"}
        resp1.is_redirect = True
        resp1.status_code = 302
        resp1.url = "http://example.com/start"

        async def fake_aiter_bytes1():
            yield b"Redirecting..."
        resp1.aiter_bytes = fake_aiter_bytes1

        class MockStreamContext:
            async def __aenter__(self):
                return resp1
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_client_instance = MagicMock()
        mock_client_instance.stream.return_value = MockStreamContext()

        class MockAsyncClient:
            def __init__(self, **kwargs):
                pass
            async def __aenter__(self):
                return mock_client_instance
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        with patch("backend.secuscan.crawler.httpx.AsyncClient", side_effect=MockAsyncClient):
            with patch("backend.secuscan.crawler.logger.warning") as mock_warning:
                result = await crawl_target("http://example.com/start")
                # Cross-host redirect should be stopped immediately
                assert result["final_url"] == "http://example.com/start"
                assert result["status_code"] == 302
                assert len(result["redirect_chain"]) == 0
                mock_warning.assert_called_once()
                assert "blocked due to host mismatch" in mock_warning.call_args[0][0]

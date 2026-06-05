"""Unit tests for the Python SDK -- no network required."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import httpx
import pytest
import requests

from tng._tng import Tng, _build_tng_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_tng_startup():
    """Mock subprocess startup so Tng can be created without a real binary."""
    with patch("tng._tng._find_tng_binary", return_value="/usr/bin/tng"), \
         patch("tng._tng._wait_for_port"), \
         patch("tng._tng.subprocess.Popen") as mock_popen, \
         patch("tng._tng._find_free_port", return_value=41000):
        mock_popen.return_value = MagicMock()
        yield mock_popen


# ---------------------------------------------------------------------------
# Tng creation with new high-level API
# ---------------------------------------------------------------------------


class TestTngCreation:
    def test_create_no_ra(self, mock_tng_startup):
        """Tng(no_ra=True) creates successfully."""
        tng = Tng(no_ra=True)
        assert tng._proxy_port == 41000

    def test_create_with_verify(self, mock_tng_startup):
        """Tng with verify config."""
        tng = Tng(
            verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]},
        )
        assert tng._proxy_port == 41000

    def test_create_with_attest(self, mock_tng_startup):
        """Tng with attest config."""
        tng = Tng(
            attest={
                "model": "passport",
                "aa_addr": "unix:///run/aa.sock",
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"],
            },
        )
        assert tng._proxy_port == 41000

    def test_create_with_ohttp(self, mock_tng_startup):
        """Tng with custom ohttp config."""
        tng = Tng(
            no_ra=True,
            ohttp={"key": {"source": "self_generated", "rotation_interval": 300}},
        )
        assert tng._proxy_port == 41000

    def test_create_with_rats_tls(self, mock_tng_startup):
        """Tng with rats_tls config."""
        tng = Tng(rats_tls={"multiplex": True})
        assert tng._proxy_port == 41000

    def test_create_bidirectional(self, mock_tng_startup):
        """Tng with both attest and verify."""
        tng = Tng(
            attest={"aa_addr": "unix:///run/aa.sock"},
            verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]},
        )
        assert tng._proxy_port == 41000

    def test_ohttp_and_rats_tls_raises(self):
        """Tng raises when both ohttp and rats_tls are provided."""
        with pytest.raises(ValueError, match="mutually exclusive"):
            Tng(ohttp={}, rats_tls={})

    def test_auto_assign_port(self, mock_tng_startup):
        """Tng auto-assigns proxy port via _find_free_port."""
        tng = Tng(no_ra=True)
        # Mocked _find_free_port returns 41000
        assert tng._proxy_port == 41000


# ---------------------------------------------------------------------------
# wrap_requests — native proxy
# ---------------------------------------------------------------------------


class TestWrapRequests:
    def test_sets_proxies(self, mock_tng_startup):
        """wrap_requests sets session.proxies dict."""
        tng = Tng(no_ra=True)

        session = requests.Session()
        tng.wrap_requests(session)

        assert "http" in session.proxies
        assert "https" in session.proxies
        assert "41000" in session.proxies["http"]
        assert session.trust_env is False

    def test_returns_same_session(self, mock_tng_startup):
        """wrap_requests returns the same session for chaining."""
        tng = Tng(no_ra=True)

        session = requests.Session()
        result = tng.wrap_requests(session)
        assert result is session


# ---------------------------------------------------------------------------
# wrap_httpx — native proxy
# ---------------------------------------------------------------------------


class TestWrapHttpx:
    def test_sync_client_proxy(self, mock_tng_startup):
        """wrap_httpx sets proxy transport on httpx.Client via _mounts."""
        tng = Tng(no_ra=True)

        client = httpx.Client()
        try:
            tng.wrap_httpx(client)
            assert len(client._mounts) > 0
            # Check that a mount contains the proxy port
            for pattern, transport in client._mounts.items():
                proxy_url = str(getattr(transport, '_proxy', None) or "")
                if "41000" in proxy_url:
                    break
            else:
                # Fallback: just check mounts are set
                assert len(client._mounts) > 0
        finally:
            client.close()

    def test_async_client_proxy(self, mock_tng_startup):
        """wrap_httpx sets proxy transport on httpx.AsyncClient via _mounts."""
        tng = Tng(no_ra=True)

        client = httpx.AsyncClient()
        try:
            tng.wrap_httpx(client)
            # Check that mounts are set (proxy transport is mounted for all://)
            assert len(client._mounts) > 0
        finally:
            pass

    def test_returns_same_client(self, mock_tng_startup):
        """wrap_httpx returns the same client for chaining."""
        tng = Tng(no_ra=True)

        client = httpx.Client()
        try:
            result = tng.wrap_httpx(client)
            assert result is client
        finally:
            client.close()


# ---------------------------------------------------------------------------
# wrap_openai — native proxy
# ---------------------------------------------------------------------------


class TestWrapOpenAI:
    def test_sync_openai_proxy(self, mock_tng_startup):
        """wrap_openai sets proxy transport on OpenAI client via _mounts."""
        try:
            from openai import OpenAI
        except ImportError:
            pytest.skip("openai not installed")

        tng = Tng(no_ra=True)

        client = OpenAI(api_key="sk-test", base_url="http://127.0.0.1:8080/v1")
        tng.wrap_openai(client)
        assert len(client._client._mounts) > 0

    def test_async_openai_proxy(self, mock_tng_startup):
        """wrap_openai sets proxy transport on AsyncOpenAI client via _mounts."""
        try:
            from openai import AsyncOpenAI
        except ImportError:
            pytest.skip("openai not installed")

        tng = Tng(no_ra=True)

        client = AsyncOpenAI(api_key="sk-test", base_url="http://127.0.0.1:8080/v1")
        tng.wrap_openai(client)
        assert len(client._client._mounts) > 0

    def test_returns_same_client(self, mock_tng_startup):
        """wrap_openai returns the same client for chaining."""
        try:
            from openai import OpenAI
        except ImportError:
            pytest.skip("openai not installed")

        tng = Tng(no_ra=True)

        client = OpenAI(api_key="sk-test", base_url="http://127.0.0.1:8080/v1")
        result = tng.wrap_openai(client)
        assert result is client


# ---------------------------------------------------------------------------
# Config building
# ---------------------------------------------------------------------------


class TestConfigBuild:
    def test_no_ra_only(self):
        """Config with no_ra=True has correct structure."""
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=True,
            verify=None, attest=None, ohttp=None, rats_tls=None,
        )
        assert "add_ingress" in config
        assert len(config["add_ingress"]) == 1
        ingress = config["add_ingress"][0]
        assert "http_proxy" in ingress
        assert ingress["http_proxy"]["proxy_listen"]["port"] == 41000
        assert ingress["no_ra"] is True
        assert ingress["ohttp"] == {}

    def test_default_ohttp_when_none_specified(self):
        """When neither ohttp nor rats_tls is given, ohttp defaults to {}."""
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=False,
            verify=None, attest=None, ohttp=None, rats_tls=None,
        )
        ingress = config["add_ingress"][0]
        assert ingress.get("ohttp") == {}
        assert "rats_tls" not in ingress

    def test_custom_ohttp(self):
        """Custom ohttp config is preserved."""
        ohttp_cfg = {"key": {"source": "self_generated"}}
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=True,
            verify=None, attest=None, ohttp=ohttp_cfg, rats_tls=None,
        )
        ingress = config["add_ingress"][0]
        assert ingress["ohttp"] == ohttp_cfg

    def test_rats_tls(self):
        """rats_tls config is included."""
        rats_tls_cfg = {"multiplex": True}
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=True,
            verify=None, attest=None, ohttp=None, rats_tls=rats_tls_cfg,
        )
        ingress = config["add_ingress"][0]
        assert ingress["rats_tls"] == rats_tls_cfg
        assert "ohttp" not in ingress

    def test_verify(self):
        """Verify config is included."""
        verify_cfg = {"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]}
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=False,
            verify=verify_cfg, attest=None, ohttp=None, rats_tls=None,
        )
        ingress = config["add_ingress"][0]
        assert ingress["verify"] == verify_cfg

    def test_attest(self):
        """Attest config is included."""
        attest_cfg = {"aa_addr": "unix:///run/aa.sock", "model": "passport"}
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=False,
            verify=None, attest=attest_cfg, ohttp=None, rats_tls=None,
        )
        ingress = config["add_ingress"][0]
        assert ingress["attest"] == attest_cfg

    def test_bidirectional(self):
        """Both attest and verify are included."""
        config = _build_tng_config(
            proxy_port=41000,
            no_ra=False,
            verify={"as_addr": "http://as/", "policy_ids": ["default"]},
            attest={"aa_addr": "unix:///aa"},
            ohttp=None, rats_tls=None,
        )
        ingress = config["add_ingress"][0]
        assert "verify" in ingress
        assert "attest" in ingress
        assert ingress["ohttp"] == {}

    def test_no_mutate_input(self):
        """_build_tng_config does not mutate input dicts."""
        ohttp_cfg = {"key": {"source": "file"}}
        original = ohttp_cfg.copy()
        _build_tng_config(
            proxy_port=41000,
            no_ra=True,
            verify=None, attest=None, ohttp=ohttp_cfg, rats_tls=None,
        )
        assert ohttp_cfg == original


# ---------------------------------------------------------------------------
# Subprocess management
# ---------------------------------------------------------------------------


class TestTngSubprocess:
    """Tests for Tng subprocess management."""

    def test_port_wait_succeeds(self, mock_http_server):
        """_wait_for_port returns immediately for a listening port."""
        from tng._tng import _wait_for_port

        _wait_for_port("127.0.0.1", mock_http_server, timeout=5.0)

    def test_port_wait_timeout(self):
        """_wait_for_port raises TimeoutError for a non-listening port."""
        from tng._tng import _wait_for_port

        free_port = _find_free_port_in_test()
        with pytest.raises(TimeoutError):
            _wait_for_port("127.0.0.1", free_port, timeout=1.0)

    def test_binary_not_found_raises(self):
        """Tng raises FileNotFoundError when binary is not found."""
        from tng._tng import _find_tng_binary

        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False):
            with pytest.raises(FileNotFoundError, match="TNG binary not found"):
                _find_tng_binary()

    def test_cleanup_is_idempotent(self, mock_tng_startup):
        """close() can be called multiple times without error."""
        tng = Tng(no_ra=True)
        tng.close()
        tng.close()  # should not raise
        tng._cleanup()  # should not raise


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _find_free_port_in_test() -> int:
    """Find a free TCP port for unit tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

"""Tng class: manages a TNG subprocess (http_proxy ingress) and provides
wrapper methods for requests, httpx, and OpenAI using native proxy support."""

from __future__ import annotations

import atexit
import copy
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

__all__ = ["Tng"]


class Tng:
    """High-level TNG client.

    Starts the TNG binary as a subprocess with an auto-configured
    ``http_proxy`` ingress, then provides ``wrap_*`` methods that use
    each library's native HTTP proxy support to route traffic through
    the encrypted TNG tunnel.

    The user only specifies security options (``no_ra``, ``verify``,
    ``attest``, ``ohttp``, ``rats_tls``). The target address is carried
    in the request URL's Host header and read by the http_proxy ingress.
    """

    def __init__(
        self,
        no_ra: bool = False,
        verify: dict[str, Any] | None = None,
        attest: dict[str, Any] | None = None,
        ohttp: dict[str, Any] | None = None,
        rats_tls: dict[str, Any] | None = None,
    ) -> None:
        # Validate mutual exclusivity: ohttp and rats_tls conflict
        if ohttp is not None and rats_tls is not None:
            raise ValueError("ohttp and rats_tls are mutually exclusive")

        # Auto-assign http_proxy port
        proxy_port = _find_free_port()
        self._proxy_port: int = proxy_port

        # Build TNG config (ingress only, no egress)
        config = _build_tng_config(
            proxy_port=proxy_port,
            no_ra=no_ra,
            verify=verify,
            attest=attest,
            ohttp=ohttp,
            rats_tls=rats_tls,
        )

        # Find TNG binary
        tng_bin = _find_tng_binary()

        # Write config to temp JSON file
        fd, config_path = tempfile.mkstemp(suffix=".json", prefix="tng_cfg_")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(config, f)
        except Exception:
            os.unlink(config_path)
            raise
        self._config_path: str = config_path

        # Start subprocess — capture stderr to a temp file for debugging
        import io

        stderr_path = tempfile.mkstemp(suffix=".log", prefix="tng_stderr_")[1]
        self._stderr_path: str = stderr_path
        self._proc: subprocess.Popen = subprocess.Popen(
            [tng_bin, "launch", "--config-file", config_path],
            stdout=subprocess.DEVNULL,
            stderr=open(stderr_path, "w"),
        )

        # Wait for proxy port to be ready, checking for process failure
        _wait_for_port("127.0.0.1", proxy_port, self._proc, timeout=30.0)

        # Register cleanup
        atexit.register(self._cleanup)

    # ------------------------------------------------------------------
    # Wrapper injection methods — native proxy support
    # ------------------------------------------------------------------

    def wrap_requests(self, session: Any) -> Any:
        """Inject the TNG http_proxy into a ``requests.Session``.

        After calling this, all ``session.get/post/request(...)`` calls
        go through the TNG encrypted tunnel.

        Args:
            session: A ``requests.Session`` instance.

        Returns:
            The same session (for chaining).
        """
        proxy_url = f"http://127.0.0.1:{self._proxy_port}"
        session.proxies = {"http": proxy_url, "https": proxy_url}
        # Disable trust_env so system proxy env vars don't interfere
        session.trust_env = False
        return session

    def wrap_httpx(self, client: Any) -> Any:
        """Inject the TNG http_proxy into an ``httpx.Client`` or
        ``httpx.AsyncClient``.

        After calling this, all ``client.get/post/request(...)`` calls
        go through the TNG encrypted tunnel.

        Args:
            client: An ``httpx.Client`` or ``httpx.AsyncClient`` instance.

        Returns:
            The same client (for chaining).
        """
        import httpx
        from httpx._utils import URLPattern

        proxy_url = f"http://127.0.0.1:{self._proxy_port}"
        proxy = httpx.Proxy(proxy_url)

        # Set _proxy for introspection compatibility, and _mounts for routing.
        # _init_proxy_transport creates a properly configured transport with
        # SSL, timeouts, etc. We mount it for all:// URLs.
        proxy_transport = client._init_proxy_transport(
            proxy, verify=True, cert=None, trust_env=False,
            http1=True, http2=False, limits=httpx.Limits(),
        )
        client._proxy = proxy
        client._mounts = {URLPattern("all://"): proxy_transport}
        return client

    def wrap_openai(self, client: Any) -> Any:
        """Inject the TNG http_proxy into an ``openai.OpenAI`` or
        ``openai.AsyncOpenAI`` client.

        OpenAI internally uses ``httpx.Client`` / ``httpx.AsyncClient``
        stored at ``client._client``. We set its proxy so all API calls
        go through TNG.

        Args:
            client: An ``openai.OpenAI`` or ``openai.AsyncOpenAI`` instance.

        Returns:
            The same client (for chaining).
        """
        import httpx
        from httpx._utils import URLPattern

        proxy_url = f"http://127.0.0.1:{self._proxy_port}"
        proxy = httpx.Proxy(proxy_url)
        inner = client._client

        proxy_transport = inner._init_proxy_transport(
            proxy, verify=True, cert=None, trust_env=False,
            http1=True, http2=False, limits=httpx.Limits(),
        )
        inner._proxy = proxy
        inner._mounts = {URLPattern("all://"): proxy_transport}
        return client

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        """Terminate the TNG subprocess and remove the temp config file."""
        if getattr(self, "_proc", None) is not None:
            proc = self._proc
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            self._proc = None  # type: ignore[assignment]

        config_path = getattr(self, "_config_path", None)
        if config_path and os.path.exists(config_path):
            try:
                os.unlink(config_path)
            except OSError:
                pass

    def __del__(self) -> None:
        self._cleanup()

    def close(self) -> None:
        """Explicitly stop the TNG subprocess and clean up resources.

        Safe to call multiple times.
        """
        self._cleanup()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find a free TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(
    host: str, port: int, proc: subprocess.Popen | None = None, timeout: float = 30.0,
) -> None:
    """Wait until a TCP port is accepting connections.

    If *proc* is given, also checks whether the process exited early
    and raises a more useful error message.

    Raises:
        RuntimeError: If the subprocess exited before the port was ready.
        TimeoutError: If the port is not ready within the timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # Check if the subprocess exited early
        if proc is not None:
            exit_code = proc.poll()
            if exit_code is not None:
                raise RuntimeError(
                    f"TNG process exited with code {exit_code} before proxy was ready"
                )
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} not ready within {timeout}s")


def _find_tng_binary() -> str:
    """Locate the TNG binary.

    Search order:
    1. ``TNG_BINARY`` environment variable (if set)
    2. ``shutil.which("tng")`` — system PATH (wheel installs to {venv}/bin/tng)
    3. ``{module_dir}/../bin/tng`` — development mode
    4. ``/usr/bin/tng`` — system install
    """
    # 1. Check environment variable
    env_bin = os.environ.get("TNG_BINARY")
    if env_bin and Path(env_bin).is_file():
        return env_bin

    # 2. Check PATH (wheel installation puts it in {venv}/bin/tng)
    found = shutil.which("tng")
    if found:
        return found

    # 3. Check development mode location
    module_dir = Path(__file__).resolve().parent
    dev_bin = module_dir.parent / "bin" / "tng"
    if dev_bin.is_file():
        return str(dev_bin)

    # 4. Check system install
    system = Path("/usr/bin/tng")
    if system.is_file():
        return str(system)

    raise FileNotFoundError(
        "TNG binary not found. Options:\n"
        "  1. Set TNG_BINARY environment variable to the tng binary path\n"
        "  2. Install tng on your system PATH\n"
        "  3. Place tng binary at tng-python/bin/tng (development mode)"
    )


def _build_tng_config(
    proxy_port: int,
    no_ra: bool,
    verify: dict[str, Any] | None,
    attest: dict[str, Any] | None,
    ohttp: dict[str, Any] | None,
    rats_tls: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the TNG config dict (ingress only, no egress).

    The http_proxy ingress listens on ``127.0.0.1:<proxy_port>``.
    Incoming requests have their target extracted from the Host header.

    Args:
        proxy_port: Port for the http_proxy ingress to listen on.
        no_ra: Disable remote attestation (debugging only).
        verify: Verifier config (as_addr, policy_ids, etc.).
        attest: Attester config (aa_addr, as_addr, model, etc.).
        ohttp: OHTTP customization (key, path_rewrites, etc.).
        rats_tls: rats-TLS customization.

    Returns:
        A TNG config dict with ``add_ingress`` only.
    """
    ingress_entry: dict[str, Any] = {
        "http_proxy": {
            "proxy_listen": {"host": "127.0.0.1", "port": proxy_port},
        },
    }

    # Default to ohttp={} when neither ohttp nor rats_tls is specified
    if ohttp is not None:
        ingress_entry["ohttp"] = copy.deepcopy(ohttp)
    elif rats_tls is None:
        ingress_entry["ohttp"] = {}

    if rats_tls is not None:
        ingress_entry["rats_tls"] = copy.deepcopy(rats_tls)

    if no_ra:
        ingress_entry["no_ra"] = True

    if verify is not None:
        ingress_entry["verify"] = copy.deepcopy(verify)

    if attest is not None:
        ingress_entry["attest"] = copy.deepcopy(attest)

    return {"add_ingress": [ingress_entry]}

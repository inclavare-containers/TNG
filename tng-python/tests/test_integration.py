"""Integration tests for the Python SDK.

Test architecture:
- **TngServer**: TNG process with `add_egress` (mapping to mock backend)
- **TngClient**: Python SDK `Tng()` with `add_ingress` (http_proxy)

To run E2E tests, a TNG binary must be available:
    make bin-build
    cd tng-python && pytest tests/test_integration.py -v -m e2e
"""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import requests

from tng import Tng


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Mock server code (used by session-scoped fixtures in conftest.py)
# ---------------------------------------------------------------------------


ENHANCED_SERVER_CODE = """
import http.server, sys, json, hashlib
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()
    def _handle(self):
        cl = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(cl) if cl > 0 else b''
        body_hash = hashlib.sha256(body).hexdigest()
        resp = {"status": "ok", "method": self.command, "path": self.path,
                "body_len": len(body), "body_hash": body_hash,
                "echo_headers": dict(self.headers)}
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Request-Method', self.command)
        self.send_header('X-Request-Path', self.path)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(json.dumps(resp).encode())
    def log_message(self, fmt, *args): pass
if __name__ == '__main__':
    port = int(sys.argv[1])
    server = http.server.HTTPServer(('127.0.0.1', port), Handler)
    print(f"Enhanced mock server on port {port}", flush=True)
    server.serve_forever()
"""

SSE_SERVER_CODE = """
import http.server, sys, time

class SSEHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if '?sse=true' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            delay = 0.1
            if 'delay=' in self.path:
                for p in self.path.split('&'):
                    if p.startswith('delay='):
                        delay = float(p.split('=')[1])
            for i in range(5):
                self.wfile.write(f"id: {i}\\ndata: event_{i}\\n\\n".encode())
                self.wfile.flush()
                time.sleep(delay)
            self.wfile.write("data: [DONE]\\n\\n".encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            self.wfile.write("data: ready\\n\\n".encode())
    def do_POST(self):
        cl = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(cl) if cl > 0 else b''
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        resp = {"status": "ok", "method": "POST", "body_len": len(body)}
        self.wfile.write(json.dumps(resp).encode())
    def log_message(self, fmt, *args): pass

import json
if __name__ == '__main__':
    port = int(sys.argv[1])
    server = http.server.HTTPServer(('127.0.0.1', port), SSEHandler)
    print(f"SSE mock server on port {port}", flush=True)
    server.serve_forever()
"""


# ---------------------------------------------------------------------------
# E2E Tests — requests through TNG proxy tunnel
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestProxyE2EWithRequests:
    """E2E tests for HTTP requests through the TNG proxy egress."""

    def test_get_through_proxy(self, tng_proxy_egress):
        """GET request through TNG proxy egress returns 200 with JSON."""
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)

        resp = session.get(f"http://127.0.0.1:{egress_port}/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_post_through_proxy(self, tng_proxy_egress):
        """POST with JSON body through TNG proxy egress."""
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)

        resp = session.post(
            f"http://127.0.0.1:{egress_port}/api/test",
            json={"key": "value"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["method"] == "POST"
        assert data["body_length"] > 0

    def test_large_body_through_proxy(self, tng_proxy_egress):
        """1MB body through TNG proxy egress."""
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)

        large_body = "A" * (1024 * 1024)
        resp = session.post(
            f"http://127.0.0.1:{egress_port}/",
            json={"data": large_body},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["body_length"] > 1024 * 1024

    def test_concurrent_requests_through_proxy(self, tng_proxy_egress):
        """5 concurrent requests through proxy, all succeed."""
        tng, egress_port = tng_proxy_egress
        results = []
        errors = []

        def make_request():
            session = requests.Session()
            tng.wrap_requests(session)
            try:
                resp = session.get(f"http://127.0.0.1:{egress_port}/")
                results.append(resp.status_code)
            except Exception as e:
                errors.append(str(e))

        threads = []
        for _ in range(5):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Errors: {errors}"
        assert len(results) == 5
        assert all(r == 200 for r in results)

    def test_http_methods_through_proxy(self, tng_proxy_egress):
        """PUT, DELETE, PATCH, HEAD through proxy."""
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)
        url = f"http://127.0.0.1:{egress_port}/resource"

        # PUT
        resp = session.put(url, json={"name": "updated"})
        assert resp.status_code == 200
        assert resp.json()["method"] == "PUT"

        # DELETE
        resp = session.delete(url)
        assert resp.status_code == 200
        assert resp.json()["method"] == "DELETE"

        # PATCH
        resp = session.patch(url, json={"name": "patched"})
        assert resp.status_code == 200
        assert resp.json()["method"] == "PATCH"

        # HEAD
        resp = session.head(f"http://127.0.0.1:{egress_port}/")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# E2E Tests — httpx through TNG proxy tunnel
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestProxyE2EWithHttpx:
    """E2E tests for httpx through the TNG proxy egress."""

    def test_sync_get(self, tng_proxy_egress):
        """GET request through proxy using httpx.Client."""
        tng, egress_port = tng_proxy_egress
        client = httpx.Client()
        try:
            tng.wrap_httpx(client)
            resp = client.get(f"http://127.0.0.1:{egress_port}/")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
        finally:
            client.close()

    def test_sync_post(self, tng_proxy_egress):
        """POST request through proxy using httpx.Client."""
        tng, egress_port = tng_proxy_egress
        client = httpx.Client()
        try:
            tng.wrap_httpx(client)
            resp = client.post(
                f"http://127.0.0.1:{egress_port}/api/data",
                json={"key": "httpx_value"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["method"] == "POST"
            assert data["body_length"] > 0
        finally:
            client.close()


# ---------------------------------------------------------------------------
# E2E Tests — OpenAI through TNG proxy tunnel
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestProxyE2EWithOpenAI:
    """E2E tests for OpenAI client through the TNG proxy egress."""

    def test_chat_completion(self, tng_proxy_egress):
        """OpenAI client uses TNG proxy — request reaches mock server."""
        tng, egress_port = tng_proxy_egress

        from openai import OpenAI

        client = OpenAI(
            api_key="sk-test-key",
            base_url=f"http://127.0.0.1:{egress_port}/v1",
        )
        tng.wrap_openai(client)

        # Verify TNG proxy is injected
        assert client._client._proxy is not None
        assert len(client._client._mounts) > 0

        # The request goes through the TNG tunnel to the mock server.
        # The mock returns JSON (not OpenAI format), so parsing fails,
        # but the HTTP request itself succeeds through the tunnel.
        import httpx
        resp = client._client.get(f"http://127.0.0.1:{egress_port}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# SSE / Streaming Tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def mock_sse_port():
    """Start a mock SSE server."""
    port = _find_free_port()

    proc = subprocess.Popen(
        [sys.executable, "-c", SSE_SERVER_CODE, str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port("127.0.0.1", port):
        proc.kill()
        raise RuntimeError(f"SSE server failed to start on port {port}")

    yield port
    proc.kill()
    proc.wait(timeout=5)


@pytest.fixture(scope="function")
def tng_sse_server(mock_sse_port):
    """Start a TNG server with egress mapping to the SSE mock server."""
    import os
    import tempfile

    egress_port = _find_free_port()

    config = {
        "add_egress": [{
            "mapping": {
                "in": {"host": "127.0.0.1", "port": egress_port},
                "out": {"host": "127.0.0.1", "port": mock_sse_port},
            },
            "ohttp": {},
            "no_ra": True,
        }],
    }

    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="tng_sse_cfg_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)

    from conftest import _find_tng_binary
    tng_bin = _find_tng_binary()
    proc = subprocess.Popen(
        [tng_bin, "launch", "--config-file", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if not _wait_for_port("127.0.0.1", egress_port):
        proc.kill()
        proc.wait(timeout=5)
        os.unlink(config_path)
        raise RuntimeError(f"TNG SSE server failed on port {egress_port}")

    yield egress_port, proc

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    try:
        os.unlink(config_path)
    except OSError:
        pass


@pytest.fixture(scope="function")
def tng_sse_proxy(tng_sse_server):
    """TngClient + TngServer for SSE streaming tests."""
    from tng import Tng

    egress_port, _server_proc = tng_sse_server
    tng = Tng(no_ra=True)
    yield tng, egress_port
    tng.close()


@pytest.mark.e2e
class TestStreamingAndIntegrity:
    """SSE streaming and body integrity tests through TNG proxy."""

    def test_sse_streaming_through_proxy(self, tng_sse_proxy):
        """SSE response through proxy, verify multiple chunks."""
        tng, egress_port = tng_sse_proxy
        session = requests.Session()
        tng.wrap_requests(session)

        url = f"http://127.0.0.1:{egress_port}/?sse=true&delay=0.1"
        resp = session.get(url, stream=True)

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("Content-Type", "")

        chunks = list(resp.iter_content(chunk_size=64))
        assert len(chunks) >= 2, f"Expected >= 2 streaming chunks, got {len(chunks)}"

        full_body = b"".join(chunks).decode()
        assert "id: 0" in full_body
        assert "id: 4" in full_body

    def test_body_integrity(self, tng_proxy_egress):
        """Verify body passes through TNG tunnel correctly."""
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)

        body = b"Hello TNG tunnel!"
        expected_len = len(body)

        resp = session.post(
            f"http://127.0.0.1:{egress_port}/",
            data=body,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["body_length"] == expected_len

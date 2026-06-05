"""Shared fixtures for integration tests."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


_tng_log_failures = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Track failed tests so we can attach TNG logs to the summary."""
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" and rep.failed:
        log_path = getattr(item, "_tng_log_path", None)
        if log_path and os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    log_content = f.read()
                _tng_log_failures.append((rep.nodeid, log_content))
            except Exception:
                pass


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print TNG server logs for failed tests at the end of the test session."""
    if _tng_log_failures:
        terminalreporter.write_sep("=", "TNG Server Logs (failed tests)")
        for nodeid, log_content in _tng_log_failures:
            terminalreporter.write_line(f"\n--- {nodeid} ---")
            terminalreporter.write_line(log_content)


def _find_free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def free_port():
    """Return a free TCP port number."""
    return _find_free_port()


def _find_tng_binary() -> str:
    """Locate the TNG binary for tests."""
    # 1. Check PATH
    found = shutil.which("tng")
    if found:
        return found
    # 2. Check built from source
    repo_root = Path(__file__).resolve().parent.parent.parent
    for binary in ["target/release/tng", "target/debug/tng"]:
        candidate = repo_root / binary
        if candidate.exists():
            return str(candidate)
    # 3. System install
    system = Path("/usr/bin/tng")
    if system.is_file():
        return str(system)
    pytest.skip("tng binary not found (need 'make bin-build' or 'yum install tng')")


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


@pytest.fixture(scope="session")
def mock_http_server(free_port):
    """Start a simple HTTP server that returns JSON for any request.

    Yields the port number. The server is killed when the fixture is torn down.
    """
    port = free_port

    server_script = Path(__file__).parent / "_mock_server.py"
    if not server_script.exists():
        server_script.write_text("""
import http.server
import sys
import json

class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle()
    def do_POST(self):
        self._handle()
    def do_PUT(self):
        self._handle()
    def do_DELETE(self):
        self._handle()
    def do_PATCH(self):
        self._handle()
    def do_HEAD(self):
        self._handle()

    def _handle(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Request-Method', self.command)
        self.send_header('X-Request-Path', self.path)
        self.end_headers()

        response = json.dumps({
            "status": "ok",
            "method": self.command,
            "path": self.path,
            "body_len": len(body),
        })
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    port = int(sys.argv[1])
    server = http.server.HTTPServer(('127.0.0.1', port), MockHandler)
    print(f"Mock server listening on port {port}", flush=True)
    server.serve_forever()
""")

    proc = subprocess.Popen(
        [sys.executable, str(server_script), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError(f"Mock HTTP server failed to start on port {port}")

    yield port

    proc.kill()
    proc.wait(timeout=5)


@pytest.fixture(scope="function")
def tng_server(mock_http_server):
    """Start a TNG server process with egress mapping to mock_http_server.

    This is the remote TngServer side: receives OHTTP-encrypted traffic,
    decrypts, and forwards to the mock backend.

    Yields:
        (egress_port, process): The egress listen port and subprocess handle.
    """
    import json
    import tempfile

    egress_port = _find_free_port()

    config = {
        "add_egress": [{
            "mapping": {
                "in": {"host": "127.0.0.1", "port": egress_port},
                "out": {"host": "127.0.0.1", "port": mock_http_server},
            },
            "ohttp": {},
            "no_ra": True,
        }],
    }

    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="tng_server_cfg_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)

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
        raise RuntimeError(f"TNG server failed to start on port {egress_port}")

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
def tng_proxy_egress(tng_server):
    """Start TngClient (http_proxy ingress) + TngServer (egress → mock).

    This is the full end-to-end fixture:
    - TngServer: receives OHTTP traffic, decrypts, forwards to mock_http_server
    - TngClient: http_proxy ingress, accepts local proxy requests

    Usage:
        tng, egress_port = tng_proxy_egress
        session = requests.Session()
        tng.wrap_requests(session)
        resp = session.get(f"http://127.0.0.1:{egress_port}/api/data")

    Yields:
        (tng, egress_port): Tng instance and the TngServer egress port.
    """
    from tng import Tng

    egress_port, _server_proc = tng_server
    tng = Tng(no_ra=True)
    yield tng, egress_port
    tng.close()


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
            "body_length": len(body),
        })
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        # Suppress logs during tests
        pass

if __name__ == '__main__':
    port = int(sys.argv[1])
    server = http.server.HTTPServer(('127.0.0.1', port), MockHandler)
    print(f"Mock server listening on port {port}", flush=True)
    server.serve_forever()

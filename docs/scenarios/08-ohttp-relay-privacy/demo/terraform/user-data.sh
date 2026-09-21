#!/bin/bash
# cloud-init for the TNG OHTTP relay demo ECS.
#
# Provisions the server side fully at boot (no SSH needed):
#   1. TNG egress (OHTTP gateway) in mapping mode: listens on :9000, forwards
#      decrypted plaintext to the echo on :8080 (no_ra).
#   2. Python echo backend on :8080 (behind the egress).
#   3. nginx TLS-terminating reverse proxy on :8443 to localhost:9000.
#   4. acme.sh issues a Let's Encrypt IP certificate for the ECS's public IP
#      (short-lived, 6-day, auto-renewed). The FC relay connects over HTTPS
#      and verifies the cert normally (LE is a public CA).
#
# For production: replace the acme.sh IP-cert block with your own domain +
# certificate (configure nginx with your cert/key file paths). IP certificates
# are for demo/eval only.
#
# This file is rendered by Terraform templatefile(). The TNG repo block is
# conditionally written when var.tng_rpm_repo_url is non-empty.
set -euo pipefail

%{ if tng_rpm_repo_url != "" }
cat > /etc/yum.repos.d/tng.repo <<EOFR
[tng]
name=TNG
baseurl=${tng_rpm_repo_url}
enabled=1
gpgcheck=0
EOFR
%{ endif }

yum install -y trusted-network-gateway python3 nginx socat curl

# --- Echo backend -------------------------------------------------------
cat > /usr/local/bin/tng-echo.py <<'EOFPY'
#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Echo(BaseHTTPRequestHandler):
    def _send(self):
        payload = {
            "x_real_ip": self.headers.get("X-Real-IP"),
            "x_forwarded_for": self.headers.get("X-Forwarded-For"),
            "tcp_source": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
        }
        data = json.dumps(payload, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        self._send()
    def do_POST(self):
        self._send()
    def log_message(self, fmt, *args):
        import sys
        sys.stderr.write(fmt % args + "\n")

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Echo).serve_forever()
EOFPY
chmod +x /usr/local/bin/tng-echo.py

cat > /etc/systemd/system/tng-echo.service <<'EOFS'
[Unit]
Description=TNG OHTTP echo backend
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/tng-echo.py 8080
Restart=always
[Install]
WantedBy=multi-user.target
EOFS

# --- TNG egress ---------------------------------------------------------
mkdir -p /etc/tng
cat > /etc/tng/egress.json <<'EOFCFG'
{
  "add_egress": [
    {
      "mapping": { "in": { "host": "127.0.0.1", "port": 9000 }, "out": { "host": "127.0.0.1", "port": 8080 } },
      "ohttp": { "key": { "source": "self_generated", "rotation_interval": 300 } },
      "no_ra": true
    }
  ]
}
EOFCFG

cat > /etc/systemd/system/tng-egress.service <<'EOFS'
[Unit]
Description=TNG egress (OHTTP gateway)
After=network.target tng-echo.service
[Service]
ExecStart=/usr/bin/tng launch --config-file /etc/tng/egress.json
Restart=always
[Install]
WantedBy=multi-user.target
EOFS

systemctl daemon-reload
systemctl enable --now tng-echo.service
systemctl enable --now tng-egress.service

# --- nginx TLS (self-signed first, LE upgrade after) ---------------------
# Generate a self-signed cert + start nginx FIRST, so :8443 always listens
# even if acme.sh fails (port 80 auto-restricted, LE rate limits, etc.).
# The FC relay uses rejectUnauthorized=false, so self-signed works.
EIP="$(curl -s --max-time 10 http://100.100.100.200/latest/meta-data/eipv4 || curl -s --max-time 10 ifconfig.me)"
mkdir -p /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/relay.crt ] && [ -n "$EIP" ]; then
    openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/ssl/relay.key \
        -out /etc/nginx/ssl/relay.crt -days 365 -nodes \
        -subj "/CN=$EIP" -addext "subjectAltName=IP:$EIP" 2>/dev/null || true
fi

cat > /etc/nginx/conf.d/tng-ohttp-relay.conf <<'EONGINX'
server {
    listen 8443 ssl http2;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/relay.crt;
    ssl_certificate_key /etc/nginx/ssl/relay.key;
    location / {
        proxy_pass http://localhost:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass_request_body on;
        proxy_http_version 1.1;
    }
}
EONGINX
systemctl enable --now nginx
systemctl restart nginx 2>/dev/null || true

# --- Let's Encrypt IP certificate (async best-effort upgrade) ------------
# For production: replace with your own domain + certificate. IP certificates
# are demo-only; production uses domain certificates.
# Runs as a one-shot systemd service so cloud-init exits immediately;
# acme.sh retries in the background without blocking boot.
cat > /usr/local/bin/tng-le-upgrade.sh <<'EOLE'
#!/bin/bash
set +e
EIP="$(curl -s --max-time 10 http://100.100.100.200/latest/meta-data/eipv4 || curl -s --max-time 10 ifconfig.me)"
[ -z "$EIP" ] && exit 0
curl https://get.acme.sh | sh -s email=demo@tng.ohttp-relay
export PATH="$HOME/.acme.sh:$PATH"
for i in $(seq 1 5); do
    if acme.sh --issue --server letsencrypt -d "$EIP" --standalone --certificate-profile shortlived 2>/dev/null; then
        acme.sh --install-cert -d "$EIP" \
            --key-file /etc/nginx/ssl/relay.key \
            --fullchain-file /etc/nginx/ssl/relay.crt \
            --reloadcmd "systemctl reload nginx" 2>/dev/null
        exit 0
    fi
    sleep 30
done
EOLE
chmod +x /usr/local/bin/tng-le-upgrade.sh
cat > /etc/systemd/system/tng-le-upgrade.service <<'EOLE2'
[Unit]
Description=TNG LE IP cert upgrade (best-effort)
After=nginx.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/tng-le-upgrade.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOLE2
systemctl daemon-reload
systemctl enable tng-le-upgrade.service
systemctl start tng-le-upgrade.service &

echo "=== TNG OHTTP relay demo ECS provisioned ==="
echo "EIP: $EIP"
echo "TLS: https://$EIP:8443 (self-signed, LE upgrade in background)"
echo "egress: localhost:9000 (mapping mode, no_ra)"
echo "echo: localhost:8080 (behind egress)"

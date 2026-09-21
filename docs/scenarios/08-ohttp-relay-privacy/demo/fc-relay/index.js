// FC 3.0 built-in Node.js HTTP handler (unified signature).
//
// Adapted from Cloudflare's privacy-gateway-relay worker, widened for TNG:
// accept any message/ohttp* content-type (TNG uses message/ohttp-chunked-req
// / -res) and forward the x-tng-ohttp-api header that the TNG egress uses to
// demux OHTTP APIs, plus the body and the chunked response, verbatim to the
// gateway (EGRESS_URL). The relay never decrypts OHTTP; it is a blind
// forwarder, so it learns the client IP but only ever sees ciphertext.
//
// FC 3.0 unified the handler signature: (event, context) -> {statusCode,
// headers, body, isBase64Encoded}. The event is a JSON string with the HTTP
// request {rawPath, headers, queryParameters, body, isBase64Encoded,
// requestContext} where requestContext.http.{method,path} carry the method.

const http = require('http');
const https = require('https');

const EGRESS_URL = process.env.EGRESS_URL;

function methodOf(req) {
  const rc = req.requestContext || {};
  const h = rc.http || {};
  return h.method || rc.method || '';
}
function pathOf(req) {
  const rc = req.requestContext || {};
  const h = rc.http || {};
  return (h.path || req.rawPath || req.path || '').replace(/\?.*$/, '');
}

exports.handler = async (event, context) => {
  if (!EGRESS_URL) {
    return { statusCode: 500, headers: { 'content-type': 'text/plain' }, body: 'EGRESS_URL not set' };
  }

  const req = JSON.parse(event.toString());
  const method = methodOf(req);
  const path = pathOf(req);
  const rawHeaders = req.headers || {};
  const headers = {};
  for (const k of Object.keys(rawHeaders)) headers[k.toLowerCase()] = rawHeaders[k];

  // GET /metadata: tiny health blob (no forwarding).
  if (method === 'GET' && path.endsWith('/metadata')) {
    // Discover the FC function's own egress IP (for narrowing the ECS SG).
    let egressIp = 'unknown';
    try {
      egressIp = await new Promise((resolve) => {
        const r = https.get('https://api.ip.sb/ip', (res) => {
          let d = ''; res.on('data', (c) => d += c); res.on('end', () => resolve(d.trim()));
        });
        r.on('error', () => resolve('unknown'));
        r.setTimeout(5000, () => { r.destroy(); resolve('unknown'); });
      });
    } catch { egressIp = 'unknown'; }
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: 'tng-ohttp', target: EGRESS_URL, egress_ip: egressIp }),
    };
  }

  if (method !== 'POST') {
    return { statusCode: 400, headers: { 'content-type': 'text/plain' }, body: 'Invalid request' };
  }

  // Blind forwarder: forward any POST with the x-tng-ohttp-api header to the
  // egress, regardless of content-type. That covers BOTH the TNG flows:
  //   - key-config (plain application/json, x-tng-ohttp-api: /tng/key-config,
  //     fetched BEFORE encryption)
  //   - tunnel (message/ohttp-chunked-req, x-tng-ohttp-api: /tng/tunnel,
  //     the OHTTP ciphertext)
  // The egress demuxes by the header; the relay never inspects content.
  const contentType = headers['content-type'] || '';

  // The request body (binary-safe): base64-decode if the platform encoded it.
  const body = req.isBase64Encoded
    ? Buffer.from(req.body || '', 'base64')
    : Buffer.from(req.body || '');

  // Demo: log the relay's view (ciphertext) when LOG_REQUEST_BODY=true.
  // Default off (production); the demo script turns it on via TF_VAR_fc_log_request_body.
  if (process.env.LOG_REQUEST_BODY === 'true') {
    const preview = body.toString('utf8', 0, Math.min(body.length, 200));
    console.log(JSON.stringify({ api: headers['x-tng-ohttp-api'], contentType, bodyLen: body.length, bodyPreview: preview }));
  }

  // Forward body + content-type + x-tng-ohttp-api to the egress gateway.
  const upstream = new URL(EGRESS_URL);
  const clientLib = upstream.protocol === 'https:' ? https : http;
  const upstreamRes = await new Promise((resolve) => {
    const r = clientLib.request(
      {
        method: 'POST',
        host: upstream.hostname,
        port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
        path: upstream.pathname + upstream.search,
        headers: {
          'content-type': contentType,
          'x-tng-ohttp-api': headers['x-tng-ohttp-api'] || '',
          'content-length': Buffer.byteLength(body),
        },
        // Demo: skip cert verification (works with LE IP cert or self-signed
        // fallback). Production: remove this + use a verified domain certificate.
        rejectUnauthorized: false,
      },
      (upRes) => {
        const ch = [];
        upRes.on('data', (c) => ch.push(c));
        upRes.on('end', () =>
          resolve({ status: upRes.statusCode || 200, headers: upRes.headers, body: Buffer.concat(ch) })
        );
        upRes.on('error', (e) =>
          resolve({
            status: 502,
            headers: { 'content-type': 'text/plain' },
            body: Buffer.from('Upstream error: ' + e.message),
          })
        );
      }
    );
    r.on('error', (e) =>
      resolve({
        status: 502,
        headers: { 'content-type': 'text/plain' },
        body: Buffer.from('Upstream error: ' + e.message),
      })
    );
    r.end(body);
  });

  // Return the OHTTP response binary-safe (base64). OHTTP bodies are binary.
  return {
    statusCode: upstreamRes.status,
    headers: { 'content-type': upstreamRes.headers['content-type'] || 'application/octet-stream' },
    body: upstreamRes.body.toString('base64'),
    isBase64Encoded: true,
  };
};

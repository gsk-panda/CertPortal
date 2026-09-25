'use strict';

// Minimal stand-in for the CertPortal agent API, used by install-test.ps1.
// Accepts enrollment token "test-token", answers job polls with 204 and counts
// them. GET /_stats reports what it has seen.

const http = require('http');

const PORT = parseInt(process.env.PORT || '8787', 10);
const stats = { enrolls: 0, polls: 0, lastAuth: null, lastVersion: null };

http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    if (req.method === 'POST' && req.url === '/api/agent/enroll') {
      const { token } = JSON.parse(body || '{}');
      if (token !== 'test-token') { res.writeHead(401); return res.end('bad token'); }
      stats.enrolls++;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ agentId: 'agent-1', agentSecret: 'secret-1' }));
    }
    if (req.method === 'GET' && req.url === '/api/agent/jobs') {
      stats.polls++;
      stats.lastAuth = req.headers.authorization || null;
      stats.lastVersion = req.headers['x-agent-version'] || null;
      return setTimeout(() => { res.writeHead(204); res.end(); }, 1000);
    }
    if (req.url === '/_stats') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(stats));
    }
    res.writeHead(404); res.end();
  });
}).listen(PORT, '127.0.0.1', () => console.log(`mock control plane on :${PORT}`));

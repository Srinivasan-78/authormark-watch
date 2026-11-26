import http from 'node:http';
import crypto from 'node:crypto';
import { log, warn, sanitize } from './github.mjs';

function verifyGitHubSignature(payload, signatureHeader, secret) {
  if (!secret || !signatureHeader || !signatureHeader.startsWith('sha256=')) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const a = Buffer.from(signatureHeader, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createWebhookServer({
  secret = process.env.WEBHOOK_SECRET || '',
  onRepoEvent = async () => {},
} = {}) {
  return http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, service: 'authormark-watch-webhook' }));
      return;
    }

    if (req.method !== 'POST' || req.url !== '/webhook') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > 1024 * 1024) { req.destroy(); return; }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      const sig = req.headers['x-hub-signature-256'];
      if (secret && !verifyGitHubSignature(rawBody, sig, secret)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }

      let payload;
      try { payload = JSON.parse(rawBody.toString('utf8')); }
      catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
        return;
      }

      const event = req.headers['x-github-event'] || 'unknown';
      const repoName = payload?.repository?.name || null;
      const action = payload?.action || null;

      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ accepted: true, event, repo: repoName, action }));

      if (event === 'ping' || !repoName) return;
      if (event === 'repository' && action === 'created' || event === 'push' || event === 'pull_request') {
        log(`Webhook received: ${event}${action ? `:${action}` : ''} for ${repoName}`);
        Promise.resolve(onRepoEvent({ event, action, repo: repoName, payload }))
          .catch(err => warn(`Webhook handler failed for ${repoName}: ${sanitize(err.message)}`));
      }
    });
  });
}

export { verifyGitHubSignature, createWebhookServer };

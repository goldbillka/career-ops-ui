import { createHash, timingSafeEqual } from 'node:crypto';
import { hostnameOf } from './request-guard.mjs';

// Browser HTTP Basic works for the SPA's native EventSource as well as fetch;
// API clients may use Bearer. No credential is ever carried in a URL or asset.
const REALM = 'career-ops-ui';
const BASIC_USER = 'career-ops';
const MIN_TOKEN_LENGTH = 32;
const MAX_AUTH_HEADER = 4096;

function validToken(token) {
  return typeof token === 'string' && token.length >= MIN_TOKEN_LENGTH
    && token.length <= 2048 && /^[\x21-\x7e]+$/.test(token);
}

function loopback(host) {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function submittedToken(header) {
  if (typeof header !== 'string' || header.length > MAX_AUTH_HEADER) return null;
  const bearer = /^Bearer ([\x21-\x7e]+)$/i.exec(header);
  if (bearer) return bearer[1];
  const basic = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(header);
  if (!basic) return null;
  const decoded = Buffer.from(basic[1], 'base64');
  if (decoded.toString('base64') !== basic[1]) return null;
  const text = decoded.toString('utf8');
  if (!text.startsWith(`${BASIC_USER}:`)) return null;
  return text.slice(BASIC_USER.length + 1);
}

export function authGate({ bindHost = '127.0.0.1', token } = {}) {
  // Snapshot configuration at app creation: a later /api/config edit cannot
  // turn off the gate on an already listening non-loopback socket.
  const configured = validToken(token);
  const expected = configured ? createHash('sha256').update(token).digest() : null;
  const declaredExposed = !loopback(bindHost);
  return function requireAuth(req, res, next) {
    // A TLS proxy may connect to the loopback socket while forwarding a
    // public Host. Treat that as exposed too; do not infer trust solely from
    // the socket address. The Host allowlist runs before this middleware.
    const exposed = declaredExposed || !loopback(req.socket.localAddress)
      || !loopback(hostnameOf(req.headers.host));
    const protectedApp = exposed || token !== undefined;
    if (!protectedApp) return next();
    res.setHeader('Cache-Control', 'private, no-store');
    // Public liveness only. /api/health contains user-specific diagnostics.
    if ((req.method === 'GET' || req.method === 'HEAD') && req.path.toLowerCase() === '/api/ping') return next();
    if (!configured) return res.status(503).json({ error: 'authentication not configured' });
    const supplied = submittedToken(req.headers.authorization);
    if (supplied !== null) {
      const digest = createHash('sha256').update(supplied).digest();
      if (timingSafeEqual(digest, expected)) {
        res.locals.authProtected = true;
        return next();
      }
    }
    res.setHeader('WWW-Authenticate', `Basic realm="${REALM}", charset="UTF-8"`);
    return res.status(401).json({ error: 'authentication required' });
  };
}

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const TOKEN = 'test-only-authorization-secret-with-32-plus-characters';
let createApp;
let fixture;
const oldEnv = { HOST: process.env.HOST, WEB_UI_AUTH_TOKEN: process.env.WEB_UI_AUTH_TOKEN, CAREER_OPS_ROOT: process.env.CAREER_OPS_ROOT };

before(async () => {
  fixture = mkdtempSync(resolve(tmpdir(), 'auth-gate-'));
  for (const dir of ['config', 'data', 'modes']) mkdirSync(resolve(fixture, dir));
  writeFileSync(resolve(fixture, 'cv.md'), '# private cv\n');
  writeFileSync(resolve(fixture, 'config', 'profile.yml'), 'candidate:\n  full_name: Test\n');
  writeFileSync(resolve(fixture, 'portals.yml'), 'tracked_companies: []\n');
  writeFileSync(resolve(fixture, 'data', 'applications.md'), '');
  writeFileSync(resolve(fixture, 'data', 'pipeline.md'), '# pipeline\n');
  writeFileSync(resolve(fixture, 'modes', 'oferta.md'), 'oferta\n');
  process.env.CAREER_OPS_ROOT = fixture;
  ({ createApp } = await import('../server/index.mjs'));
});

after(() => {
  for (const [key, value] of Object.entries(oldEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  if (fixture) rmSync(fixture, { recursive: true, force: true });
});

async function withApp(host, token, fn) {
  process.env.HOST = host;
  if (token === undefined) delete process.env.WEB_UI_AUTH_TOKEN;
  else process.env.WEB_UI_AUTH_TOKEN = token;
  const app = createApp();
  const server = await new Promise((done) => {
    const s = app.listen(0, '127.0.0.1', () => done(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn((path, opts) => fetch(base + path, { redirect: 'manual', ...opts }), base); }
  finally { await new Promise((done) => server.close(done)); }
}

const bearer = (value = TOKEN) => ({ Authorization: `Bearer ${value}` });
const basic = (value = TOKEN) => ({ Authorization: `Basic ${Buffer.from(`career-ops:${value}`).toString('base64')}` });

test('exposed bind without a valid configured token fails closed, including the SPA and API', async () => {
  for (const token of [undefined, '', 'too-short']) {
    await withApp('0.0.0.0', token, async (get) => {
      for (const path of ['/', '/js/api.js', '/api/health', '/api/cv', '/api/stream/scan-en']) {
        const res = await get(path);
        assert.equal(res.status, 503, path);
        assert.equal(res.headers.get('cache-control'), 'private, no-store');
      }
      assert.equal((await get('/api/ping')).status, 200);
    });
  }
});

test('exposed bind blocks documents, static SPA, health, reads, writes, LLM and SSE before handlers run', async () => {
  await withApp('0.0.0.0', TOKEN, async (get) => {
    for (const path of ['/', '/arbitrary-route', '/js/api.js', '/vendor/leaflet/leaflet.js', '/api/health', '/api/cv', '/api/config', '/api/output/pdfs/fake.pdf', '/api/stream/scan-en', '/api/stream/pdf']) {
      const res = await get(path);
      assert.equal(res.status, 401, path);
      assert.equal(res.headers.get('cache-control'), 'private, no-store');
      assert.ok(res.headers.get('www-authenticate')?.startsWith('Basic '));
    }
    for (const [method, path] of [['PUT', '/api/cv'], ['POST', '/api/evaluate'], ['POST', '/api/auto-pipeline'], ['POST', '/api/config'], ['DELETE', '/api/tasks/fake']]) {
      assert.equal((await get(path, { method, headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401, `${method} ${path}`);
    }
    assert.equal(readFileSync(resolve(fixture, 'cv.md'), 'utf8'), '# private cv\n');
    assert.equal(existsSync(resolve(fixture, 'data', 'activity.jsonl')), false);
    const ping = await (await get('/api/ping')).json();
    assert.deepEqual(Object.keys(ping).sort(), ['ok', 'version']);
    assert.equal(ping.ok, true);
  });
});

test('valid bearer and browser Basic credentials unlock SPA, API, health and stream without URL token', async () => {
  await withApp('0.0.0.0', TOKEN, async (get) => {
    for (const headers of [bearer(), basic()]) {
      assert.equal((await get('/', { headers })).status, 200);
      assert.match(await (await get('/api/cv', { headers })).text(), /private cv/);
      assert.equal((await get('/api/health', { headers })).status, 200);
      assert.equal((await get('/api/stream/scan-en?source=no-such-source', { headers })).status !== 401, true);
      assert.equal((await get('/js/api.js', { headers })).status, 200);
      for (const asset of ['/favicon-16.png', '/vendor/leaflet/leaflet.js']) {
        const response = await get(asset, { headers });
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('cache-control'), 'private, no-store', asset);
      }
    }
    for (const headers of [bearer('wrong'), basic('wrong'), { Authorization: `Bearer ${TOKEN}?` }, { Authorization: `Basic ${Buffer.from(`other:${TOKEN}`).toString('base64')}` }]) {
      assert.equal((await get('/api/cv', { headers })).status, 401);
    }
    assert.equal((await get('/api/cv?token=' + encodeURIComponent(TOKEN))).status, 401);
    assert.equal((await get('/api/cv', { headers: { Cookie: `WEB_UI_AUTH_TOKEN=${TOKEN}` } })).status, 401);
  });
});

test('loopback default remains accessible without credentials and CSRF guard still rejects cross-site writes', async () => {
  await withApp('127.0.0.1', undefined, async (get) => {
    assert.equal((await get('/')).status, 200);
    assert.match(await (await get('/api/cv')).text(), /private cv/);
  });
  await withApp('0.0.0.0', TOKEN, async (get) => {
    const res = await get('/api/cv', { method: 'PUT', headers: { ...bearer(), Origin: 'https://evil.example', 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(res.status, 403);
  });
});

test('auth configuration is snapshotted and cannot be disabled by a later env change', async () => {
  process.env.HOST = '0.0.0.0';
  process.env.WEB_UI_AUTH_TOKEN = TOKEN;
  const app = createApp();
  delete process.env.WEB_UI_AUTH_TOKEN;
  process.env.HOST = '127.0.0.1';
  const server = await new Promise((done) => {
    const s = app.listen(0, '127.0.0.1', () => done(s));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/api/cv`;
    assert.equal((await fetch(url)).status, 401);
    assert.equal((await fetch(url, { headers: bearer() })).status, 200);
  } finally { await new Promise((done) => server.close(done)); }
});

test('a public Host forwarded to a loopback listener cannot bypass missing authentication', async () => {
  await withApp('127.0.0.1', undefined, async (_get, base) => {
    // Node fetch overwrites Host; use the HTTP client to model a proxy.
    const request = (path) => new Promise((done, reject) => {
      http.get(base + path, { headers: { Host: '192.0.2.10' } }, (res) => {
        res.resume();
        res.on('end', () => done(res.statusCode));
      }).on('error', reject);
    });
    assert.equal(await request('/api/cv'), 503);
    assert.equal(await request('/'), 503);
    assert.equal(await request('/api/ping'), 200);
  });
});

test('authorized write reaches the fixture while rejected cross-site write does not', async () => {
  await withApp('0.0.0.0', TOKEN, async (get) => {
    const body = JSON.stringify({ markdown: '# Updated private CV\n' });
    const options = { method: 'PUT', headers: { ...bearer(), 'Content-Type': 'application/json' }, body };
    const rejected = await get('/api/cv', { ...options, headers: { ...options.headers, Origin: 'https://evil.example' } });
    assert.equal(rejected.status, 403);
    assert.equal(readFileSync(resolve(fixture, 'cv.md'), 'utf8'), '# private cv\n');
    const accepted = await get('/api/cv', options);
    assert.equal(accepted.status, 200);
    assert.equal(readFileSync(resolve(fixture, 'cv.md'), 'utf8'), '# Updated private CV\n');
  });
});

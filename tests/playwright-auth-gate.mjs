import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const require = createRequire(import.meta.url);
let playwright;
for (const candidate of ['playwright', 'playwright-core', resolve(process.cwd(), '..', 'node_modules', 'playwright')]) {
  try { playwright = require(candidate); break; } catch { /* optional browser dependency */ }
}
const TOKEN = 'browser-test-only-secret-with-32-plus-characters';
let fixture, appServer, browser, origin;
const oldEnv = { HOST: process.env.HOST, WEB_UI_AUTH_TOKEN: process.env.WEB_UI_AUTH_TOKEN, CAREER_OPS_ROOT: process.env.CAREER_OPS_ROOT };

before(async () => {
  if (!playwright) return;
  fixture = mkdtempSync(resolve(tmpdir(), 'auth-browser-'));
  for (const dir of ['config', 'data', 'modes']) mkdirSync(resolve(fixture, dir));
  writeFileSync(resolve(fixture, 'cv.md'), '# Private CV\n');
  writeFileSync(resolve(fixture, 'config', 'profile.yml'), 'candidate:\n  full_name: Test\n');
  writeFileSync(resolve(fixture, 'portals.yml'), 'tracked_companies: []\n');
  writeFileSync(resolve(fixture, 'data', 'applications.md'), '');
  writeFileSync(resolve(fixture, 'data', 'pipeline.md'), '# Pipeline\n');
  writeFileSync(resolve(fixture, 'modes', 'oferta.md'), '# Oferta\n');
  process.env.CAREER_OPS_ROOT = fixture;
  process.env.HOST = '0.0.0.0';
  process.env.WEB_UI_AUTH_TOKEN = TOKEN;
  const { createApp } = await import('../server/index.mjs');
  const app = createApp();
  appServer = await new Promise((done) => {
    const server = app.listen(0, '127.0.0.1', () => done(server));
  });
  origin = `http://127.0.0.1:${appServer.address().port}`;
  browser = await playwright.chromium.launch({ headless: true,
    ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}) });
});

after(async () => {
  if (browser) await browser.close();
  if (appServer) {
    appServer.closeAllConnections?.();
    await new Promise((done) => appServer.close(done));
  }
  for (const [key, value] of Object.entries(oldEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  if (fixture) rmSync(fixture, { recursive: true, force: true });
});

test('Chromium requires credentials before loading SPA, then carries Basic auth on API and EventSource', { skip: !playwright }, async () => {
  const anonymous = await browser.newContext();
  try {
    const page = await anonymous.newPage();
    const anonymousResponse = await anonymous.request.get(origin + '/');
    assert.equal(anonymousResponse.status(), 401);
    await assert.rejects(page.goto(origin + '/'), /ERR_INVALID_AUTH_CREDENTIALS/);

  } finally { await anonymous.close(); }

  const authenticated = await browser.newContext({ httpCredentials: { username: 'career-ops', password: TOKEN } });
  try {
    const page = await authenticated.newPage();
    const response = await page.goto(origin + '/');
    assert.equal(response.status(), 200);
    await page.waitForFunction(() => !!window.API);
    const cv = await page.evaluate(() => window.API.getText('/api/cv'));
    assert.match(cv, /Private CV/);
    const streamResponse = page.waitForResponse((res) => res.url().includes('/api/stream/unknown-auth-probe'));
    await page.evaluate(() => { window.__authProbe = new EventSource('/api/stream/unknown-auth-probe'); });
    assert.equal((await streamResponse).status(), 404, 'SSE GET must pass authentication even though route does not exist');
    await page.evaluate(() => window.__authProbe.close());
  } finally { await authenticated.close(); }
});

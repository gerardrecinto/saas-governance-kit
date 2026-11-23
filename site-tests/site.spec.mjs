import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const docs = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'docs');
const SITE = 'https://gerardrecinto.github.io/saas-governance-kit/';

// The CI badge comes from github.com at runtime. It is the only third-party request on the page,
// and a blocked or offline load of it is not a page error.
const isBadgeNoise = (text) => /actions\/workflows\/ci\.yml\/badge\.svg|ERR_(INTERNET_DISCONNECTED|NAME_NOT_RESOLVED|BLOCKED)/.test(text);

test('no console errors or page errors', async ({ page }) => {
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error' && !isBadgeNoise(m.text() + (m.location().url || ''))) problems.push(m.text()); });
  page.on('pageerror', (e) => problems.push(String(e)));
  await page.goto('./');
  await page.waitForLoadState('load');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(300);
  expect(problems).toEqual([]);
});

for (const width of [375, 1440]) {
  test(`no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('./');
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);
    const { sw, cw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
    expect(sw).toBeLessThanOrEqual(cw);
    // Nothing should poke out of the viewport even though body hides overflow.
    const offenders = await page.evaluate(() => {
      const w = document.documentElement.clientWidth;
      return [...document.querySelectorAll('main *, header *, footer *')]
        .filter((el) => { const r = el.getBoundingClientRect(); return r.width > 0 && (r.right > w + 1 || r.left < -1) && !el.closest('pre') && !el.closest('.flow'); })
        .map((el) => el.tagName.toLowerCase() + '.' + el.className)
        .slice(0, 5);
    });
    expect(offenders).toEqual([]);
  });
}

test('reduced motion shows every section and card', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('./');
  const hidden = await page.evaluate(() =>
    [...document.querySelectorAll('section, .card, .reveal')]
      .filter((el) => Number(getComputedStyle(el).opacity) < 1 || getComputedStyle(el).visibility === 'hidden')
      .map((el) => el.id || el.className));
  expect(hidden).toEqual([]);
  expect(await page.locator('main section').count()).toBeGreaterThanOrEqual(5);
});

test('content is visible with JavaScript disabled', async ({ browser }) => {
  const ctx = await browser.newContext({ javaScriptEnabled: false, baseURL: 'http://127.0.0.1:4173/saas-governance-kit/' });
  const page = await ctx.newPage();
  await page.goto('./');
  for (const id of ['flow', 'quick-start', 'features', 'validated', 'links']) {
    await expect(page.locator(`#${id}`)).toBeVisible();
    expect(await page.locator(`#${id}`).evaluate((el) => getComputedStyle(el).opacity)).toBe('1');
  }
  await expect(page.locator('.copy').first()).toBeHidden();
  await ctx.close();
});

test('copy button copies the command', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('./');
  const btn = page.locator('button[data-target="cmd-install"]');
  await btn.scrollIntoViewIfNeeded();
  await btn.click();
  await expect(btn).toHaveText('Copied');
  const text = await page.evaluate(() => navigator.clipboard.readText());
  expect(text).toContain('pip install -e ".[dev]"');
  expect(text).toContain('pytest -q');
});

test('internal links, anchors and assets resolve', async ({ page, request }) => {
  const html = await readFile(join(docs, 'index.html'), 'utf8');
  await page.goto('./');
  const refs = await page.evaluate(() =>
    [...document.querySelectorAll('[href], [src]')].map((el) => el.getAttribute('href') ?? el.getAttribute('src')));
  expect(refs.length).toBeGreaterThan(10);
  for (const ref of refs) {
    if (/^(https?:)?\/\//.test(ref)) {
      expect(ref.startsWith('https://')).toBe(true);
      continue;
    }
    if (ref.startsWith('#')) {
      const id = ref.slice(1);
      if (id) expect(await page.locator(`[id="${id}"]`).count(), `anchor ${ref}`).toBe(1);
      continue;
    }
    const res = await request.get(new URL(ref, page.url()).toString());
    expect(res.status(), ref).toBe(200);
  }
  // Absolute URLs that point at this site must also exist locally.
  for (const m of html.matchAll(new RegExp(SITE.replace(/[.]/g, '\\.') + '([^"\\s<]*)', 'g'))) {
    const res = await request.get(new URL(m[1] || './', page.url()).toString());
    expect(res.status(), m[0]).toBe(200);
  }
  for (const f of ['robots.txt', 'sitemap.xml', 'favicon.svg', 'og-image.png', '404.html']) {
    expect((await request.get(new URL(f, page.url()).toString())).status(), f).toBe(200);
  }
});

/**
 * Playwright test to debug the WASM proof-generation abort.
 *
 * Goal: capture the "[check FAIL] ..." printf from the wasm_check_override.h
 * (or any other console output) that fires before the abort() in lf_prove_direct.
 *
 * Run with:
 *   npx playwright test verifier/test/wasm-debug.spec.mjs --reporter=line --timeout=120000
 * or:
 *   node verifier/test/run-wasm-debug.mjs
 */

import { test, expect, chromium } from '@playwright/test';

const ISSUER_URL  = 'http://localhost:3001';
const HOLDER_URL  = 'http://localhost:3002';
const VERIFIER_URL = 'http://localhost:3003';

test.setTimeout(180_000); // 3 min — proof generation takes ~30s

test('WASM proof generation — capture abort details', async () => {
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const context = await browser.newContext();

  // ── collect ALL console output from the holder page ──────────────────────
  const consoleLogs = [];
  const page = await context.newPage();

  page.on('console', msg => {
    const text = `[${msg.type()}] ${msg.text()}`;
    consoleLogs.push(text);
    console.log('[HOLDER CONSOLE]', text);
  });

  page.on('pageerror', err => {
    const text = `[pageerror] ${err.message}\n${err.stack || ''}`;
    consoleLogs.push(text);
    console.log('[HOLDER PAGEERROR]', text);
  });

  // ── Step 1: issue a credential ────────────────────────────────────────────
  console.log('\n=== Step 1: issue credential ===');
  const issuerPage = await context.newPage();
  await issuerPage.goto(ISSUER_URL);
  await issuerPage.waitForLoadState('networkidle');

  // Fill age and generate offer
  const ageInput = issuerPage.locator('input[type="number"], input[name="age"], input[placeholder*="age" i], #age').first();
  await ageInput.fill('22');

  const genBtn = issuerPage.locator('button').filter({ hasText: /generate/i }).first();
  await genBtn.click();
  await issuerPage.waitForTimeout(1000);

  // Grab the credential offer URI from wherever the issuer puts it
  let credentialOfferUri = null;
  // Try textarea or input with openid-credential-offer://
  const offerElements = await issuerPage.locator('textarea, input[type="text"]').all();
  for (const el of offerElements) {
    const val = await el.inputValue().catch(() => '');
    if (val.startsWith('openid-credential-offer://')) {
      credentialOfferUri = val;
      break;
    }
  }
  if (!credentialOfferUri) {
    // Try getting it from any visible text
    const body = await issuerPage.textContent('body');
    const m = body.match(/openid-credential-offer:\/\/[^\s"'<]+/);
    if (m) credentialOfferUri = m[0];
  }
  console.log('Credential offer URI:', credentialOfferUri?.substring(0, 80) + '...');
  expect(credentialOfferUri).toBeTruthy();

  // ── Step 2: add credential to holder wallet ───────────────────────────────
  console.log('\n=== Step 2: holder fetches credential ===');
  await page.goto(HOLDER_URL);
  await page.waitForLoadState('networkidle');

  // Click "Add Credential"
  const addCredBtn = page.locator('button').filter({ hasText: /add credential/i }).first();
  await addCredBtn.click();
  await page.waitForTimeout(500);

  // Paste URI into input
  const uriInput = page.locator('input[type="text"], textarea').first();
  await uriInput.fill(credentialOfferUri);

  const fetchBtn = page.locator('button').filter({ hasText: /fetch credential/i }).first();
  await fetchBtn.click();

  // Wait for success indication
  await page.waitForFunction(() => {
    const body = document.body.innerText;
    return body.includes('stored') || body.includes('Credential') && body.includes('added')
      || body.includes('success') || body.includes('age_above');
  }, { timeout: 30_000 }).catch(() => console.log('Timeout waiting for credential fetch success'));

  await page.waitForTimeout(1000);
  console.log('Holder page after fetch:', (await page.textContent('body')).substring(0, 200));

  // ── Step 3: create a VP request on the verifier ───────────────────────────
  console.log('\n=== Step 3: create VP request ===');
  const vpResp = await fetch(`${VERIFIER_URL}/create-request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: ['age_above_21'] }),
  });
  const vpData = await vpResp.json();
  const vpUri = vpData.request_uri;
  const sessionId = vpData.session_id;
  console.log('VP request URI (truncated):', vpUri?.substring(0, 80) + '...');
  console.log('Session ID:', sessionId);
  expect(vpUri).toBeTruthy();

  // ── Step 4: holder parses & approves the VP request ──────────────────────
  console.log('\n=== Step 4: holder parses VP request ===');

  // Find the VP URI input and Parse button
  const vpInput = page.locator('input[type="text"], textarea').last();
  await vpInput.fill(vpUri);

  const parseBtn = page.locator('button').filter({ hasText: /parse request/i }).first();
  await parseBtn.click();
  await page.waitForTimeout(2000);

  console.log('Holder page after parse:', (await page.textContent('body')).substring(0, 300));

  // ── Step 5: approve & generate proof ─────────────────────────────────────
  console.log('\n=== Step 5: approve & generate proof (WASM) ===');
  const approveBtn = page.locator('button').filter({ hasText: /approve|generate proof/i }).first();
  await approveBtn.click();

  console.log('Waiting for proof generation (up to 90s)...');

  // Wait for either success or error — WASM should abort
  await page.waitForFunction(() => {
    const body = document.body.innerText;
    return body.includes('proof submitted') ||
           body.includes('Proof submitted') ||
           body.includes('Verified') ||
           body.includes('error') ||
           body.includes('Error') ||
           body.includes('failed') ||
           body.includes('Failed') ||
           body.includes('falling back');
  }, { timeout: 90_000 }).catch(() => console.log('Timeout waiting for proof result'));

  await page.waitForTimeout(3000);

  // ── Step 6: dump all collected console logs ───────────────────────────────
  console.log('\n=== ALL HOLDER CONSOLE LOGS ===');
  consoleLogs.forEach(l => console.log(l));

  console.log('\n=== HOLDER PAGE BODY ===');
  const finalBody = await page.textContent('body');
  console.log(finalBody.substring(0, 1000));

  // ── Step 7: check verifier session ───────────────────────────────────────
  console.log('\n=== Step 7: verifier session result ===');
  const sessResp = await fetch(`${VERIFIER_URL}/session/${sessionId}`);
  const sessData = await sessResp.json();
  console.log('Session state:', JSON.stringify(sessData, null, 2));

  await browser.close();

  // Fail loudly if we see the abort in the logs
  const abortLogs = consoleLogs.filter(l =>
    l.includes('Aborted') || l.includes('abort') || l.includes('check FAIL') || l.includes('FAIL')
  );
  if (abortLogs.length > 0) {
    console.log('\n=== ABORT-RELATED LOGS ===');
    abortLogs.forEach(l => console.log(l));
  }
});

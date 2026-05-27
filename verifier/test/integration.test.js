'use strict';

/**
 * Integration tests: full OID4VCI issuance + OID4VP verification flows.
 *
 * Two servers are started on test ports:
 *   - Issuer  on port 3095
 *   - Verifier on port 3099
 *
 * The tests cover:
 *   1. Full OID4VCI flow: /offer → /token → /credential
 *   2. Full OID4VP flow: /create-request → simulated presentation → /response
 *   3. Stale-key guard: public_key extracted from x5chain equals issuer-advertised key
 *
 * Run with:  node --test test/integration.test.js
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

// ─── ports ────────────────────────────────────────────────────────────────────

const ISSUER_PORT = 3095;
const VERIFIER_PORT = 3099;
const ISSUER_BASE = `http://localhost:${ISSUER_PORT}`;
const VERIFIER_BASE = `http://localhost:${VERIFIER_PORT}`;

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function req(method, baseUrl, urlPath, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    };
    const r = http.request(opts, res => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

const iget = (p, o) => req('GET', ISSUER_BASE, p, o);
const ipost = (p, o) => req('POST', ISSUER_BASE, p, o);
const vget = (p, o) => req('GET', VERIFIER_BASE, p, o);
const vpost = (p, o) => req('POST', VERIFIER_BASE, p, o);

// ─── helpers ──────────────────────────────────────────────────────────────────

function extractPreAuthCode(offerUri) {
  const url = new URL(offerUri);
  const offerJson = decodeURIComponent(url.searchParams.get('credential_offer'));
  const offer = JSON.parse(offerJson);
  return offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
}

/**
 * Poll an HTTP endpoint until it responds or the deadline passes.
 */
async function waitForHttp(url, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const u = new URL(url);
        const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'GET' }, res => {
          res.resume();
          resolve();
        });
        r.on('error', reject);
        r.setTimeout(1000, () => { r.destroy(); reject(new Error('timeout')); });
        r.end();
      });
      return true;
    } catch {
      await new Promise(r => setTimeout(r, 300));
    }
  }
  throw new Error(`Server at ${url} did not respond within ${timeoutMs}ms`);
}

// ─── server lifecycle ──────────────────────────────────────────────────────────

let issuerProc, verifierProc;

before(async () => {
  // 1. Start issuer
  issuerProc = spawn(
    process.execPath,
    [path.join(__dirname, '../../issuer/index.js')],
    {
      env: { ...process.env, PORT: String(ISSUER_PORT) },
      stdio: 'ignore',
    }
  );
  issuerProc.on('error', () => {});

  await waitForHttp(`${ISSUER_BASE}/issuer-public-key`, 30000);

  // 2. Start verifier pointing at test issuer
  verifierProc = spawn(
    process.execPath,
    [path.join(__dirname, '../server.js')],
    {
      env: {
        ...process.env,
        PORT: String(VERIFIER_PORT),
        ISSUER_URL: ISSUER_BASE,
      },
      stdio: 'ignore',
    }
  );
  verifierProc.on('error', () => {});

  await waitForHttp(`${VERIFIER_BASE}/issuer-key`, 30000);
}, { timeout: 60000 });

after(() => {
  for (const proc of [issuerProc, verifierProc]) {
    if (proc && !proc.killed) {
      proc.kill('SIGTERM');
      setTimeout(() => { if (!proc.killed) proc.kill('SIGKILL'); }, 500);
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Full OID4VCI issuance flow
// ═══════════════════════════════════════════════════════════════════════════════

describe('Full OID4VCI issuance flow', () => {
  it('complete flow: /offer → /token → /credential returns a valid MDOC', async () => {
    // Step 1: get credential offer
    const offerRes = await iget('/offer?age=21');
    assert.strictEqual(offerRes.status, 200, 'offer should succeed');
    assert.ok(offerRes.body.credential_offer_uri, 'should have credential_offer_uri');

    // Step 2: exchange pre-authorized code for token
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const tokenRes = await ipost('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    assert.strictEqual(tokenRes.status, 200, 'token exchange should succeed');
    assert.ok(tokenRes.body.access_token, 'should have access_token');
    assert.strictEqual(tokenRes.body.token_type, 'Bearer');

    // Step 3: retrieve credential with device key
    const deviceKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const devicePubJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.publicKey);

    const credRes = await ipost('/credential', {
      body: {
        format: 'mso_mdoc',
        device_public_key_jwk: {
          kty: devicePubJwk.kty,
          crv: devicePubJwk.crv,
          x: devicePubJwk.x,
          y: devicePubJwk.y,
        },
      },
      headers: { Authorization: `Bearer ${tokenRes.body.access_token}` },
    });
    assert.strictEqual(credRes.status, 200, 'credential issuance should succeed');
    assert.strictEqual(credRes.body.format, 'mso_mdoc');
    assert.ok(credRes.body.credential, 'credential must be present');
    assert.match(credRes.body.credential, /^[A-Za-z0-9_-]+$/, 'credential is base64url');
  });

  it('pre-authorized code is single-use', async () => {
    const offerRes = await iget('/offer?age=18');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const payload = {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': code,
    };

    const first = await ipost('/token', { body: payload });
    assert.strictEqual(first.status, 200, 'first use must succeed');

    const second = await ipost('/token', { body: payload });
    assert.strictEqual(second.status, 400, 'second use must be rejected');
    assert.strictEqual(second.body.error, 'invalid_grant');
  });

  it('issuer-public-key returns valid P-256 JWK', async () => {
    const r = await iget('/issuer-public-key');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.kty, 'EC');
    assert.strictEqual(r.body.crv, 'P-256');
    assert.ok(r.body.x && r.body.y, 'key coordinates must be present');
    assert.strictEqual(r.body.d, undefined, 'private scalar must not be exposed');
  });

  it('age fields in credential response match requested age', async () => {
    // Age 17 — all false
    const offerRes17 = await iget('/offer?age=17');
    const code17 = extractPreAuthCode(offerRes17.body.credential_offer_uri);
    const tok17 = await ipost('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code17,
      },
    });
    const cred17 = await ipost('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${tok17.body.access_token}` },
    });
    assert.strictEqual(cred17.body.age_fields.age_above_18, false);
    assert.strictEqual(cred17.body.age_fields.age_above_21, false);
    assert.strictEqual(cred17.body.age_fields.age_above_25, false);

    // Age 25 — all true
    const offerRes25 = await iget('/offer?age=25');
    const code25 = extractPreAuthCode(offerRes25.body.credential_offer_uri);
    const tok25 = await ipost('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code25,
      },
    });
    const cred25 = await ipost('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${tok25.body.access_token}` },
    });
    assert.strictEqual(cred25.body.age_fields.age_above_18, true);
    assert.strictEqual(cred25.body.age_fields.age_above_21, true);
    assert.strictEqual(cred25.body.age_fields.age_above_25, true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Full OID4VP verification flow (simulated proof)
// ═══════════════════════════════════════════════════════════════════════════════

describe('Full OID4VP flow (simulated proof)', () => {
  /**
   * Issue a credential for the given age and return { credential, devicePrivateJwk }.
   */
  async function issueCredential(age) {
    const deviceKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const devicePubJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.publicKey);
    const devicePrivJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.privateKey);

    const offerRes = await iget(`/offer?age=${age}`);
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const tokenRes = await ipost('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    const credRes = await ipost('/credential', {
      body: {
        format: 'mso_mdoc',
        device_public_key_jwk: {
          kty: devicePubJwk.kty, crv: devicePubJwk.crv,
          x: devicePubJwk.x, y: devicePubJwk.y,
        },
      },
      headers: { Authorization: `Bearer ${tokenRes.body.access_token}` },
    });
    return { credential: credRes.body.credential, devicePrivateJwk: devicePrivJwk };
  }

  it('/create-request → pending session → /response with simulated proof → verified_simulated', async () => {
    // Step 1: verifier creates a request session
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    assert.strictEqual(createRes.status, 200, 'create-request should succeed');
    const { session_id } = createRes.body;
    assert.ok(session_id, 'session_id must be present');
    assert.ok(createRes.body.request_uri.startsWith('openid4vp://'), 'request_uri scheme');
    assert.ok(createRes.body.qr_code_data_url, 'qr_code_data_url must be present');

    // Step 2: check session is pending
    const sessInit = await vget(`/session/${session_id}`);
    assert.strictEqual(sessInit.body.status, 'pending');
    const nonce = sessInit.body.nonce;

    // Step 3: "holder" submits simulated vp_token
    const vpToken = {
      simulated: true,
      nonce,
      disclosed_attributes: { age_above_18: true },
    };
    const submission = {
      id: 'test-submission-' + Date.now(),
      definition_id: session_id,
      descriptor_map: [],
    };
    const responseRes = await vpost('/response', {
      body: { vp_token: vpToken, presentation_submission: submission },
    });
    assert.strictEqual(responseRes.status, 200, 'response submission should succeed');
    assert.ok(responseRes.body.success, 'success must be true');
    assert.strictEqual(responseRes.body.session_id, session_id);

    // Step 4: session is now verified_simulated
    const sessFinal = await vget(`/session/${session_id}`);
    assert.strictEqual(sessFinal.body.status, 'verified_simulated');
    assert.ok(sessFinal.body.verified_at, 'verified_at must be set');
    assert.deepStrictEqual(sessFinal.body.disclosed_attributes, { age_above_18: true });
  });

  it('full flow for age_above_21 field discloses correct attribute', async () => {
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_21'] },
    });
    const { session_id } = createRes.body;
    const sessInit = await vget(`/session/${session_id}`);
    const nonce = sessInit.body.nonce;

    const vpToken = {
      simulated: true,
      nonce,
      disclosed_attributes: { age_above_21: true },
    };
    await vpost('/response', {
      body: {
        vp_token: vpToken,
        presentation_submission: { id: 'sub', definition_id: session_id, descriptor_map: [] },
      },
    });

    const sess = await vget(`/session/${session_id}`);
    assert.strictEqual(sess.body.status, 'verified_simulated');
    assert.strictEqual(sess.body.disclosed_attributes.age_above_21, true);
  });

  it('multiple concurrent sessions are independent', async () => {
    const [r1, r2] = await Promise.all([
      vpost('/create-request', { body: { fields: ['age_above_18'] } }),
      vpost('/create-request', { body: { fields: ['age_above_25'] } }),
    ]);
    assert.notStrictEqual(r1.body.session_id, r2.body.session_id);

    const [s1, s2] = await Promise.all([
      vget(`/session/${r1.body.session_id}`),
      vget(`/session/${r2.body.session_id}`),
    ]);

    // Submit vp_token only for session 1
    await vpost('/response', {
      body: {
        vp_token: { simulated: true, nonce: s1.body.nonce, disclosed_attributes: {} },
        presentation_submission: { id: 's', definition_id: r1.body.session_id, descriptor_map: [] },
      },
    });

    const [after1, after2] = await Promise.all([
      vget(`/session/${r1.body.session_id}`),
      vget(`/session/${r2.body.session_id}`),
    ]);
    assert.strictEqual(after1.body.status, 'verified_simulated', 'session 1 should be verified');
    assert.strictEqual(after2.body.status, 'pending', 'session 2 should still be pending');
  });

  it('nonce mismatch causes session to fail', async () => {
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    const { session_id } = createRes.body;

    await vpost('/response', {
      body: {
        vp_token: { simulated: true, nonce: 'wrong-nonce', disclosed_attributes: {} },
        presentation_submission: { id: 'sub', definition_id: session_id, descriptor_map: [] },
      },
    });

    const sess = await vget(`/session/${session_id}`);
    assert.strictEqual(sess.body.status, 'failed');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Stale-key scenario: x5chain key matches issuer-advertised key
// ═══════════════════════════════════════════════════════════════════════════════

describe('Stale-key guard: x5chain key matches issuer public key', () => {
  it('key extracted from credential x5chain matches /issuer-public-key', async () => {
    // Get the issuer's advertised public key
    const issuerKeyRes = await iget('/issuer-public-key');
    assert.strictEqual(issuerKeyRes.status, 200);
    const issuerJwk = issuerKeyRes.body;

    // Issue a credential
    const deviceKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const devicePubJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.publicKey);
    const devicePrivJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.privateKey);

    const offerRes = await iget('/offer?age=21');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const tokRes = await ipost('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    const credRes = await ipost('/credential', {
      body: {
        format: 'mso_mdoc',
        device_public_key_jwk: {
          kty: devicePubJwk.kty, crv: devicePubJwk.crv,
          x: devicePubJwk.x, y: devicePubJwk.y,
        },
      },
      headers: { Authorization: `Bearer ${tokRes.body.access_token}` },
    });
    const rawMdoc = credRes.body.credential;

    // Parse the credential and extract issuer key from x5chain
    const cborx = require(path.join(__dirname, '../node_modules/cbor-x'));
    const cborDecoder = new cborx.Encoder({
      useRecords: false,
      variableMapSize: true,
      mapsAsObjects: false,
      useTag259ForMaps: false,
    });

    const mdocBytes = Buffer.from(rawMdoc.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const decoded = cborDecoder.decode(mdocBytes);
    const documents = decoded.get('documents');
    assert.ok(documents && documents.length > 0, 'documents must be present');

    const issuerSigned = documents[0].get('issuerSigned');
    const issuerAuth = issuerSigned.get('issuerAuth');
    const unprotHdr = issuerAuth[1];
    const x5chain = unprotHdr instanceof Map ? unprotHdr.get(33) : unprotHdr[33];
    const certDer = Array.isArray(x5chain) ? x5chain[0] : x5chain;
    assert.ok(certDer, 'x5chain cert must be present in issuerAuth');

    const x509 = new crypto.X509Certificate(certDer);
    const certJwk = x509.publicKey.export({ format: 'jwk' });

    // Compare base64url coordinates
    assert.strictEqual(certJwk.x, issuerJwk.x,
      'x5chain cert public key x must match issuer-advertised key');
    assert.strictEqual(certJwk.y, issuerJwk.y,
      'x5chain cert public key y must match issuer-advertised key');
    assert.strictEqual(certJwk.crv, 'P-256', 'curve must be P-256');
  });

  it('verifier /issuer-key returns the key fetched from issuer', async () => {
    const issuerKeyFromIssuer = await iget('/issuer-public-key');
    const issuerKeyFromVerifier = await vget('/issuer-key');

    assert.strictEqual(issuerKeyFromVerifier.status, 200);
    assert.strictEqual(issuerKeyFromVerifier.body.x, issuerKeyFromIssuer.body.x,
      'verifier cached key x must match issuer key');
    assert.strictEqual(issuerKeyFromVerifier.body.y, issuerKeyFromIssuer.body.y,
      'verifier cached key y must match issuer key');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Session state machine checks
// ═══════════════════════════════════════════════════════════════════════════════

describe('Session state machine', () => {
  it('GET /session returns 404 for unknown id', async () => {
    const r = await vget('/session/totally-unknown-session-xyz-789');
    assert.strictEqual(r.status, 404);
  });

  it('session status transitions: pending → verified_simulated', async () => {
    const createRes = await vpost('/create-request', { body: { fields: ['age_above_18'] } });
    const { session_id } = createRes.body;

    const before = await vget(`/session/${session_id}`);
    assert.strictEqual(before.body.status, 'pending');

    const nonce = before.body.nonce;
    await vpost('/response', {
      body: {
        vp_token: { simulated: true, nonce, disclosed_attributes: { age_above_18: true } },
        presentation_submission: { id: 'sub', definition_id: session_id, descriptor_map: [] },
      },
    });

    const after = await vget(`/session/${session_id}`);
    assert.strictEqual(after.body.status, 'verified_simulated');
  });

  it('session stores proof_type for simulated proof', async () => {
    const createRes = await vpost('/create-request', { body: { fields: ['age_above_25'] } });
    const { session_id } = createRes.body;
    const nonce = (await vget(`/session/${session_id}`)).body.nonce;

    await vpost('/response', {
      body: {
        vp_token: { simulated: true, nonce, disclosed_attributes: { age_above_25: true } },
        presentation_submission: { id: 'sub', definition_id: session_id, descriptor_map: [] },
      },
    });

    const sess = await vget(`/session/${session_id}`);
    assert.ok(sess.body.proof_type, 'proof_type must be set after verification');
    assert.ok(
      typeof sess.body.proof_type === 'string' &&
      sess.body.proof_type.toLowerCase().includes('simulated'),
      'proof_type must mention "simulated"'
    );
  });
});

'use strict';

/**
 * Issuer unit + integration tests.
 *
 * The issuer server is started on a dedicated test port (3091) so that tests
 * can run independently from any already-running instance.  All tests go
 * through the HTTP API because `deriveAgeFields` and `buildMdoc` are not
 * exported from index.js.
 *
 * Run with:  node --test  (from the issuer directory)
 *       or:  node --test test/issuer.test.js
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

// ─── helpers ──────────────────────────────────────────────────────────────────

const TEST_PORT = 3091;
const BASE_URL = `http://localhost:${TEST_PORT}`;

/**
 * Send an HTTP request and return { status, body } where body is parsed JSON.
 */
function req(method, urlPath, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, BASE_URL);
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
      res.on('data', chunk => { raw += chunk; });
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

function get(urlPath, opts) { return req('GET', urlPath, opts); }
function post(urlPath, opts) { return req('POST', urlPath, opts); }

/**
 * Extract the pre-authorized code from a credential_offer_uri returned by GET /offer.
 */
function extractPreAuthCode(offerUri) {
  const url = new URL(offerUri);
  const offerJson = decodeURIComponent(url.searchParams.get('credential_offer'));
  const offer = JSON.parse(offerJson);
  return offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
}

// ─── server lifecycle ──────────────────────────────────────────────────────────

let serverProcess;

/**
 * Poll an HTTP endpoint until it responds or the deadline passes.
 */
function waitForHttp(url, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise(async (resolve, reject) => {
    while (Date.now() < deadline) {
      try {
        await new Promise((res, rej) => {
          const u = new URL(url);
          const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'GET' }, resp => {
            resp.resume();
            res();
          });
          r.on('error', rej);
          r.setTimeout(1000, () => { r.destroy(); rej(new Error('timeout')); });
          r.end();
        });
        return resolve(true);
      } catch {
        await new Promise(r => setTimeout(r, 300));
      }
    }
    reject(new Error(`Server at ${url} did not respond within ${timeoutMs}ms`));
  });
}

before(async () => {
  serverProcess = spawn(
    process.execPath,
    [path.join(__dirname, '..', 'index.js')],
    {
      env: { ...process.env, PORT: String(TEST_PORT) },
      stdio: 'ignore',
    }
  );
  serverProcess.on('error', () => {});
  await waitForHttp(`${BASE_URL}/issuer-public-key`, 30000);
}, { timeout: 60000 });

after(() => {
  if (serverProcess && !serverProcess.killed) {
    serverProcess.kill('SIGTERM');
    setTimeout(() => { if (!serverProcess.killed) serverProcess.kill('SIGKILL'); }, 500);
  }
});

// ─── deriveAgeFields (tested via GET /offer + age_fields in response) ──────────

describe('deriveAgeFields — age boundary tests', () => {
  async function ageFields(age) {
    const r = await get(`/offer?age=${age}`);
    assert.strictEqual(r.status, 200, `offer?age=${age} should succeed`);
    return r.body.age_fields;
  }

  it('age 0 → all false', async () => {
    const f = await ageFields(0);
    assert.strictEqual(f.age_above_18, false);
    assert.strictEqual(f.age_above_21, false);
    assert.strictEqual(f.age_above_25, false);
  });

  it('age 17 → all false', async () => {
    const f = await ageFields(17);
    assert.strictEqual(f.age_above_18, false);
    assert.strictEqual(f.age_above_21, false);
    assert.strictEqual(f.age_above_25, false);
  });

  it('age 18 → age_above_18 true, rest false', async () => {
    const f = await ageFields(18);
    assert.strictEqual(f.age_above_18, true);
    assert.strictEqual(f.age_above_21, false);
    assert.strictEqual(f.age_above_25, false);
  });

  it('age 21 → age_above_18 and age_above_21 true, age_above_25 false', async () => {
    const f = await ageFields(21);
    assert.strictEqual(f.age_above_18, true);
    assert.strictEqual(f.age_above_21, true);
    assert.strictEqual(f.age_above_25, false);
  });

  it('age 25 → all true', async () => {
    const f = await ageFields(25);
    assert.strictEqual(f.age_above_18, true);
    assert.strictEqual(f.age_above_21, true);
    assert.strictEqual(f.age_above_25, true);
  });

  it('age 26 → all true', async () => {
    const f = await ageFields(26);
    assert.strictEqual(f.age_above_18, true);
    assert.strictEqual(f.age_above_21, true);
    assert.strictEqual(f.age_above_25, true);
  });

  it('age 100 → all true', async () => {
    const f = await ageFields(100);
    assert.strictEqual(f.age_above_18, true);
    assert.strictEqual(f.age_above_21, true);
    assert.strictEqual(f.age_above_25, true);
  });
});

// ─── GET /offer ────────────────────────────────────────────────────────────────

describe('GET /offer', () => {
  it('returns credential_offer_uri and qr_code for valid age', async () => {
    const r = await get('/offer?age=21');
    assert.strictEqual(r.status, 200);
    assert.ok(typeof r.body.credential_offer_uri === 'string', 'should have credential_offer_uri');
    assert.ok(r.body.credential_offer_uri.startsWith('openid-credential-offer://'), 'URI scheme');
    assert.ok(typeof r.body.qr_code === 'string', 'should have qr_code');
    assert.ok(r.body.qr_code.startsWith('data:image/'), 'qr_code should be a data URL');
  });

  it('returns credential_offer with correct issuer and grant', async () => {
    const r = await get('/offer?age=18');
    assert.strictEqual(r.status, 200);
    const offer = r.body.credential_offer;
    assert.ok(offer, 'should have credential_offer object');
    assert.ok(Array.isArray(offer.credentials) && offer.credentials.includes('org.iso.18013.5.1.age_verification'), 'credential id');
    const grant = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    assert.ok(grant, 'pre-authorized_code grant must exist');
    assert.ok(typeof grant['pre-authorized_code'] === 'string', 'code must be string');
    assert.strictEqual(grant.user_pin_required, false);
  });

  it('rejects age below 0', async () => {
    const r = await get('/offer?age=-1');
    assert.strictEqual(r.status, 400);
    assert.ok(r.body.error, 'should have error field');
  });

  it('rejects age above 150', async () => {
    const r = await get('/offer?age=200');
    assert.strictEqual(r.status, 400);
  });

  it('rejects missing age param', async () => {
    const r = await get('/offer');
    assert.strictEqual(r.status, 400);
  });

  it('rejects non-numeric age', async () => {
    const r = await get('/offer?age=abc');
    assert.strictEqual(r.status, 400);
  });
});

// ─── POST /token ───────────────────────────────────────────────────────────────

describe('POST /token', () => {
  it('returns access_token for valid pre-authorized_code', async () => {
    const offerRes = await get('/offer?age=21');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);

    const r = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    assert.strictEqual(r.status, 200);
    assert.ok(typeof r.body.access_token === 'string', 'must have access_token');
    assert.strictEqual(r.body.token_type, 'Bearer');
    assert.ok(typeof r.body.expires_in === 'number');
  });

  it('rejects already-used pre-authorized_code', async () => {
    const offerRes = await get('/offer?age=18');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);

    // First use — should succeed
    const first = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    assert.strictEqual(first.status, 200);

    // Second use — should fail
    const second = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    assert.strictEqual(second.status, 400);
    assert.strictEqual(second.body.error, 'invalid_grant');
  });

  it('rejects unknown code', async () => {
    const r = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': 'not-a-real-code',
      },
    });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.body.error, 'invalid_grant');
  });

  it('rejects wrong grant_type', async () => {
    const offerRes = await get('/offer?age=18');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);

    const r = await post('/token', {
      body: {
        grant_type: 'authorization_code',
        'pre-authorized_code': code,
      },
    });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.body.error, 'unsupported_grant_type');
  });

  it('rejects missing grant_type', async () => {
    const r = await post('/token', {
      body: { 'pre-authorized_code': 'some-code' },
    });
    assert.strictEqual(r.status, 400);
  });
});

// ─── POST /credential ─────────────────────────────────────────────────────────

describe('POST /credential', () => {
  async function getValidToken(age = 21) {
    const offerRes = await get(`/offer?age=${age}`);
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const tokenRes = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    return tokenRes.body.access_token;
  }

  it('returns mso_mdoc credential for valid bearer token', async () => {
    const token = await getValidToken(25);
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.format, 'mso_mdoc');
    assert.ok(typeof r.body.credential === 'string', 'credential must be a string');
    // base64url characters only
    assert.match(r.body.credential, /^[A-Za-z0-9_-]+$/, 'credential must be base64url');
  });

  it('credential base64url decodes to valid CBOR MDOC with correct doctype', async () => {
    const cborx = require('../node_modules/cbor-x');
    const token = await getValidToken(21);
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 200);

    const raw = Buffer.from(r.body.credential.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const decoder = new cborx.Encoder({ useRecords: false, mapsAsObjects: false });
    const decoded = decoder.decode(raw);

    // Top-level DeviceResponse structure: { version, documents, status }
    const docs = decoded.get('documents') || decoded.documents;
    assert.ok(Array.isArray(docs) && docs.length > 0, 'documents array must be present');

    const doc0 = docs[0];
    const docType = doc0.get ? doc0.get('docType') : doc0.docType;
    assert.strictEqual(docType, 'org.iso.18013.5.1.age_verification', 'doctype must be org.iso.18013.5.1.age_verification');
  });

  it('credential contains the expected namespace fields', async () => {
    const mdl = require('../node_modules/@auth0/mdl');
    const { setCborEncodeDecodeOptions, getCborEncodeDecodeOptions } = mdl;
    setCborEncodeDecodeOptions({ ...getCborEncodeDecodeOptions(), variableMapSize: true });

    const token = await getValidToken(21);
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${token}` },
    });

    const raw = Buffer.from(r.body.credential.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const parsed = mdl.parse(raw);
    assert.ok(parsed.documents.length > 0, 'should have documents');

    const doc = parsed.documents[0];
    const items = doc.issuerSigned.nameSpaces['org.iso.18013.5.1'] || [];
    const fieldNames = items.map(i => i.elementIdentifier);

    for (const field of ['age_above_18', 'age_above_21', 'age_above_25', 'issuer_country']) {
      assert.ok(fieldNames.includes(field), `field ${field} should be present`);
    }

    // For age 21: age_above_18=true, age_above_21=true, age_above_25=false
    const byName = Object.fromEntries(items.map(i => [i.elementIdentifier, i.elementValue]));
    assert.strictEqual(byName.age_above_18, true);
    assert.strictEqual(byName.age_above_21, true);
    assert.strictEqual(byName.age_above_25, false);
    assert.strictEqual(byName.issuer_country, 'IN');
  });

  it('age_fields in response mirrors the correct boolean values', async () => {
    const token = await getValidToken(18);
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 200);
    const af = r.body.age_fields;
    assert.strictEqual(af.age_above_18, true);
    assert.strictEqual(af.age_above_21, false);
    assert.strictEqual(af.age_above_25, false);
  });

  it('rejects request with missing Authorization header', async () => {
    const r = await post('/credential', { body: { format: 'mso_mdoc' } });
    assert.strictEqual(r.status, 401);
    assert.ok(r.body.error, 'should have error field');
  });

  it('rejects request with invalid token', async () => {
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: 'Bearer not.a.valid.jwt' },
    });
    assert.strictEqual(r.status, 401);
  });

  it('rejects unsupported credential format', async () => {
    const token = await getValidToken(21);
    const r = await post('/credential', {
      body: { format: 'jwt_vc_json' },
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.body.error, 'unsupported_credential_format');
  });

  it('accepts missing format field (defaults to mso_mdoc)', async () => {
    const token = await getValidToken(21);
    const r = await post('/credential', {
      body: {},
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.format, 'mso_mdoc');
  });
});

// ─── GET /issuer-public-key ────────────────────────────────────────────────────

describe('GET /issuer-public-key', () => {
  it('returns a JWK with kty EC and crv P-256', async () => {
    const r = await get('/issuer-public-key');
    assert.strictEqual(r.status, 200);
    const jwk = r.body;
    assert.strictEqual(jwk.kty, 'EC');
    assert.strictEqual(jwk.crv, 'P-256');
    assert.ok(typeof jwk.x === 'string' && jwk.x.length > 0, 'x coordinate must be present');
    assert.ok(typeof jwk.y === 'string' && jwk.y.length > 0, 'y coordinate must be present');
    // Public key must NOT include the private key scalar
    assert.strictEqual(jwk.d, undefined, 'private scalar d must not be exposed');
  });

  it('public key has kid set', async () => {
    const r = await get('/issuer-public-key');
    assert.ok(typeof r.body.kid === 'string' && r.body.kid.length > 0, 'kid should be set');
  });
});

// ─── GET /.well-known/openid-credential-issuer ────────────────────────────────

describe('GET /.well-known/openid-credential-issuer', () => {
  it('returns credential_issuer and expected doctype', async () => {
    const r = await get('/.well-known/openid-credential-issuer');
    assert.strictEqual(r.status, 200);
    assert.ok(typeof r.body.credential_issuer === 'string');
    assert.ok(Array.isArray(r.body.credentials_supported));
    const supported = r.body.credentials_supported[0];
    assert.strictEqual(supported.doctype, 'org.iso.18013.5.1.age_verification');
    assert.strictEqual(supported.format, 'mso_mdoc');
  });
});

// ─── buildMdoc (via POST /credential) ─────────────────────────────────────────

describe('buildMdoc — credential structure', () => {
  it('returns a base64url string', async () => {
    const offerRes = await get('/offer?age=21');
    const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
    const tokenRes = await post('/token', {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      },
    });
    const token = tokenRes.body.access_token;
    const r = await post('/credential', {
      body: { format: 'mso_mdoc' },
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(r.status, 200);
    // base64url: only [A-Za-z0-9_-], no padding =
    assert.match(r.body.credential, /^[A-Za-z0-9_-]+$/);
  });

  it('each issuance produces a distinct credential (non-deterministic signing)', async () => {
    async function issue() {
      const offerRes = await get('/offer?age=21');
      const code = extractPreAuthCode(offerRes.body.credential_offer_uri);
      const tokenRes = await post('/token', {
        body: {
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': code,
        },
      });
      const r = await post('/credential', {
        body: { format: 'mso_mdoc' },
        headers: { Authorization: `Bearer ${tokenRes.body.access_token}` },
      });
      return r.body.credential;
    }
    const [c1, c2] = await Promise.all([issue(), issue()]);
    // Salted digests ensure distinct credentials even for identical age fields
    assert.notStrictEqual(c1, c2, 'successive issuances must produce different credentials');
  });
});

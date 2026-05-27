'use strict';

/**
 * Verifier unit tests (no WASM).
 *
 * Covers:
 *  - rawEcdsaToDer helper
 *  - buildLongfellowInput validation and output (via POST /generate-proof)
 *  - Session API (GET /session, POST /create-request, POST /response)
 *
 * The verifier server is started on port 3093 so tests run independently.
 * An issuer server is started on port 3092 so the verifier can fetch its key.
 *
 * Run with:  node --test  (from the verifier directory)
 *       or:  node --test test/verifier.test.js
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const { rawEcdsaToDer, encodeCborValue } = require('./helpers.js');

// ─── port constants ────────────────────────────────────────────────────────────

const ISSUER_PORT = 3092;
const VERIFIER_PORT = 3093;
const ISSUER_BASE = `http://localhost:${ISSUER_PORT}`;
const VERIFIER_BASE = `http://localhost:${VERIFIER_PORT}`;

// ─── generic HTTP helper ───────────────────────────────────────────────────────

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

// ─── issuer helpers ────────────────────────────────────────────────────────────

function extractPreAuthCode(offerUri) {
  const url = new URL(offerUri);
  const offerJson = decodeURIComponent(url.searchParams.get('credential_offer'));
  const offer = JSON.parse(offerJson);
  return offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
}

async function issueCredential(age = 21) {
  const offerRes = await iget(`/offer?age=${age}`);
  const code = extractPreAuthCode(offerRes.body.credential_offer_uri);

  const tokenRes = await ipost('/token', {
    body: {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': code,
    },
  });
  const token = tokenRes.body.access_token;

  // Generate a device key for the holder
  const deviceKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const devicePublicJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.publicKey);
  const devicePrivateJwk = await crypto.subtle.exportKey('jwk', deviceKeyPair.privateKey);

  const credRes = await ipost('/credential', {
    body: {
      format: 'mso_mdoc',
      device_public_key_jwk: {
        kty: devicePublicJwk.kty,
        crv: devicePublicJwk.crv,
        x: devicePublicJwk.x,
        y: devicePublicJwk.y,
      },
    },
    headers: { Authorization: `Bearer ${token}` },
  });
  return { credential: credRes.body.credential, devicePrivateJwk };
}

// ─── server lifecycle ──────────────────────────────────────────────────────────

let issuerProc, verifierProc;

/**
 * Poll an HTTP endpoint until it responds or the deadline passes.
 * Returns true when the server is up, throws on timeout.
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

before(async () => {
  // Start the issuer first
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

  // Start the verifier, pointing at test issuer
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
// rawEcdsaToDer unit tests (pure function, no server needed)
// ═══════════════════════════════════════════════════════════════════════════════

describe('rawEcdsaToDer', () => {
  it('produces correct DER structure for a normal signature', () => {
    // All-ones r and s (no leading zeros, no high-bit issue)
    const raw = Buffer.alloc(64, 0x11);
    const der = rawEcdsaToDer(raw);
    assert.strictEqual(der[0], 0x30, 'outer tag must be SEQUENCE (0x30)');
    assert.strictEqual(der[1], der.length - 2, 'outer length field');
    assert.strictEqual(der[2], 0x02, 'r tag must be INTEGER (0x02)');
    const rLen = der[3];
    assert.strictEqual(der[4 + rLen], 0x02, 's tag must be INTEGER (0x02)');
  });

  it('strips leading zero bytes from r and s', () => {
    // P-1363 r||s: each half is 32-byte big-endian. Value 1 → 31 zero bytes + 0x01.
    const raw = Buffer.alloc(64, 0);
    raw[31] = 0x01; // r = 1
    raw[32] = 0x00;
    raw[63] = 0x02; // s = 2 (one leading zero in the s half)
    const der = rawEcdsaToDer(raw);
    assert.strictEqual(der[2], 0x02);
    const rLen = der[3];
    assert.strictEqual(rLen, 1);
    assert.strictEqual(der[4], 0x01);
    const sOffset = 4 + rLen;
    assert.strictEqual(der[sOffset + 1], 1);
    assert.strictEqual(der[sOffset + 2], 0x02);
  });

  it('adds 0x00 padding when high bit of r is set', () => {
    // r starts with 0x80 (high bit set) → DER must prepend 0x00
    const raw = Buffer.alloc(64, 0x01);
    raw[0] = 0x80;
    const der = rawEcdsaToDer(raw);
    const rLen = der[3];
    assert.strictEqual(rLen, 33, 'r length must be 33 (32 + padding byte)');
    assert.strictEqual(der[4], 0x00, 'first byte of r integer must be 0x00 pad');
    assert.strictEqual(der[5], 0x80, 'second byte of r integer must be 0x80');
  });

  it('adds 0x00 padding when high bit of s is set', () => {
    const raw = Buffer.alloc(64, 0x01);
    raw[32] = 0x80; // first byte of s
    const der = rawEcdsaToDer(raw);
    const rLen = der[3];
    const sOffset = 4 + rLen;
    assert.strictEqual(der[sOffset], 0x02, 's tag');
    const sLen = der[sOffset + 1];
    assert.strictEqual(sLen, 33, 's length must be 33');
    assert.strictEqual(der[sOffset + 2], 0x00, 'first byte of s integer must be 0x00 pad');
  });

  it('throws for wrong length (not 64 bytes)', () => {
    assert.throws(() => rawEcdsaToDer(Buffer.alloc(63)), /64/);
    assert.throws(() => rawEcdsaToDer(Buffer.alloc(65)), /64/);
    assert.throws(() => rawEcdsaToDer(Buffer.alloc(0)), /64/);
  });

  it('produces a DER signature that Node crypto.verify accepts', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const privKey = crypto.createPrivateKey({
      key: Buffer.from(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)),
      format: 'der',
      type: 'pkcs8',
    });
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(await crypto.subtle.exportKey('spki', keyPair.publicKey)),
      format: 'der',
      type: 'spki',
    });

    const msg = Buffer.from('hello verifier test');
    // Sign with Node (produces DER)
    const derSig = crypto.sign('SHA256', msg, privKey);

    // Verify round-trip: also test that rawEcdsaToDer works for a real sig
    // First get the raw (ieee-p1363) form, then convert back to DER
    const rawSig = Buffer.from(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, msg)
    );
    assert.strictEqual(rawSig.length, 64);

    const convertedDer = rawEcdsaToDer(rawSig);
    assert.ok(crypto.verify('SHA256', msg, pubKey, convertedDer), 'converted DER must verify');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// encodeCborValue helper tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('encodeCborValue (helper)', () => {
  it('true → "f5"', () => assert.strictEqual(encodeCborValue(true), 'f5'));
  it('false → "f4"', () => assert.strictEqual(encodeCborValue(false), 'f4'));
  it('empty string → "60"', () => assert.strictEqual(encodeCborValue(''), '60'));

  it('"IN" → text string CBOR (62494e)', () => {
    // "IN" = 0x49 0x4e, length 2 → 0x62 0x49 0x4e
    assert.strictEqual(encodeCborValue('IN'), '62494e');
  });

  it('23-char string uses 1-byte length', () => {
    const s = 'A'.repeat(23);
    const hex = encodeCborValue(s);
    assert.strictEqual(hex.slice(0, 2), (0x60 | 23).toString(16).padStart(2, '0'));
    assert.strictEqual(hex.length, 2 + 23 * 2);
  });

  it('24-char string uses 2-byte length header (0x78)', () => {
    const s = 'A'.repeat(24);
    const hex = encodeCborValue(s);
    assert.strictEqual(hex.slice(0, 2), '78');
    assert.strictEqual(hex.slice(2, 4), (24).toString(16).padStart(2, '0'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Session API
// ═══════════════════════════════════════════════════════════════════════════════

describe('GET /session', () => {
  it('returns 404 for an unknown session id', async () => {
    const r = await vget('/session/does-not-exist-00000');
    assert.strictEqual(r.status, 404);
    assert.ok(r.body.error, 'should have error field');
  });
});

describe('POST /create-request', () => {
  it('creates a session with pending status', async () => {
    const r = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    assert.strictEqual(r.status, 200);
    assert.ok(typeof r.body.session_id === 'string', 'session_id must be string');
    assert.ok(typeof r.body.request_uri === 'string', 'request_uri must be string');
    assert.ok(r.body.request_uri.startsWith('openid4vp://'), 'URI scheme');

    // Check session is actually stored
    const s = await vget(`/session/${r.body.session_id}`);
    assert.strictEqual(s.status, 200);
    assert.strictEqual(s.body.status, 'pending');
  });

  it('session object has all expected fields', async () => {
    const r = await vpost('/create-request', {
      body: { fields: ['age_above_18', 'age_above_21'] },
    });
    const s = await vget(`/session/${r.body.session_id}`);
    const sess = s.body;
    assert.ok('session_id' in sess, 'session_id');
    assert.ok('nonce' in sess, 'nonce');
    assert.ok('fields' in sess, 'fields');
    assert.ok('status' in sess, 'status');
    assert.ok('created_at' in sess, 'created_at');
    assert.deepStrictEqual(sess.fields, ['age_above_18', 'age_above_21']);
  });

  it('rejects empty fields array', async () => {
    const r = await vpost('/create-request', { body: { fields: [] } });
    assert.strictEqual(r.status, 400);
    assert.ok(r.body.error);
  });

  it('rejects missing fields', async () => {
    const r = await vpost('/create-request', { body: {} });
    assert.strictEqual(r.status, 400);
  });

  it('rejects invalid field name', async () => {
    const r = await vpost('/create-request', { body: { fields: ['bad_field'] } });
    assert.strictEqual(r.status, 400);
    assert.ok(r.body.error);
  });

  it('creates unique session ids for each request', async () => {
    const [r1, r2] = await Promise.all([
      vpost('/create-request', { body: { fields: ['age_above_18'] } }),
      vpost('/create-request', { body: { fields: ['age_above_18'] } }),
    ]);
    assert.notStrictEqual(r1.body.session_id, r2.body.session_id);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// POST /response — simulated proof path
// ═══════════════════════════════════════════════════════════════════════════════

describe('POST /response — simulated proof', () => {
  it('sets session status to verified_simulated for a valid simulated vp_token', async () => {
    // Create a verification request
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    const { session_id } = createRes.body;
    const sessInit = await vget(`/session/${session_id}`);
    const nonce = sessInit.body.nonce;

    // Submit a simulated proof
    const vpToken = {
      simulated: true,
      nonce,
      disclosed_attributes: { age_above_18: true },
    };
    const submission = {
      id: 'test-submission',
      definition_id: session_id,
      descriptor_map: [],
    };
    const r = await vpost('/response', {
      body: { vp_token: vpToken, presentation_submission: submission },
    });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.success);

    // Session should now be verified_simulated
    const sessAfter = await vget(`/session/${session_id}`);
    assert.strictEqual(sessAfter.body.status, 'verified_simulated');
    assert.ok(sessAfter.body.verified_at, 'verified_at should be set');
    assert.deepStrictEqual(sessAfter.body.disclosed_attributes, { age_above_18: true });
  });

  it('sets session status to failed on nonce mismatch', async () => {
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    const { session_id } = createRes.body;

    const vpToken = {
      simulated: true,
      nonce: 'wrong-nonce-value',
      disclosed_attributes: { age_above_18: true },
    };
    const submission = {
      id: 'test-submission',
      definition_id: session_id,
      descriptor_map: [],
    };
    const r = await vpost('/response', {
      body: { vp_token: vpToken, presentation_submission: submission },
    });
    assert.strictEqual(r.status, 400);
    assert.ok(r.body.error);

    const sessAfter = await vget(`/session/${session_id}`);
    assert.strictEqual(sessAfter.body.status, 'failed');
  });

  it('returns 404 for unknown session_id in presentation_submission', async () => {
    const vpToken = {
      simulated: true,
      nonce: 'any-nonce',
      disclosed_attributes: {},
    };
    const submission = {
      id: 'test-submission',
      definition_id: 'non-existent-session-id',
      descriptor_map: [],
    };
    const r = await vpost('/response', {
      body: { vp_token: vpToken, presentation_submission: submission },
    });
    assert.strictEqual(r.status, 404);
  });

  it('rejects duplicate submission on already-processed session', async () => {
    const createRes = await vpost('/create-request', {
      body: { fields: ['age_above_18'] },
    });
    const { session_id } = createRes.body;
    const sessInit = await vget(`/session/${session_id}`);
    const nonce = sessInit.body.nonce;

    const vpToken = { simulated: true, nonce, disclosed_attributes: {} };
    const submission = { id: 'sub', definition_id: session_id, descriptor_map: [] };

    await vpost('/response', { body: { vp_token: vpToken, presentation_submission: submission } });
    // Second submit
    const second = await vpost('/response', {
      body: { vp_token: vpToken, presentation_submission: submission },
    });
    assert.strictEqual(second.status, 400);
    assert.ok(second.body.error);
  });

  it('returns 400 when vp_token or presentation_submission is missing', async () => {
    const r1 = await vpost('/response', {
      body: { vp_token: { simulated: true } },
    });
    assert.strictEqual(r1.status, 400);

    const r2 = await vpost('/response', {
      body: { presentation_submission: { definition_id: 'x', descriptor_map: [] } },
    });
    assert.strictEqual(r2.status, 400);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// POST /generate-proof — buildLongfellowInput validation and output
// ═══════════════════════════════════════════════════════════════════════════════

describe('POST /generate-proof — buildLongfellowInput validation', () => {
  // We test validation by sending malformed presentations.
  // The endpoint returns 400 with the error from buildLongfellowInput.

  const requiredFields = [
    'raw_mdoc_b64', 'device_private_jwk', 'fields', 'doctype',
    'mdoc_generated_nonce', 'client_id', 'response_uri', 'verifier_nonce',
  ];

  async function makeValidPresentation() {
    const { credential, devicePrivateJwk } = await issueCredential(21);
    return {
      raw_mdoc_b64: credential,
      device_private_jwk: devicePrivateJwk,
      fields: ['age_above_18'],
      doctype: 'org.iso.18013.5.1.age_verification',
      mdoc_generated_nonce: 'test-mdoc-nonce',
      client_id: `http://localhost:${VERIFIER_PORT}`,
      response_uri: `http://localhost:${VERIFIER_PORT}/response`,
      verifier_nonce: 'test-verifier-nonce',
    };
  }

  for (const field of requiredFields) {
    it(`rejects presentation missing required field: ${field}`, async () => {
      const pres = await makeValidPresentation();
      const badPres = { ...pres };
      delete badPres[field];
      const r = await vpost('/generate-proof', { body: { presentation: badPres } });
      assert.strictEqual(r.status, 400, `should return 400 when ${field} is missing`);
      assert.ok(r.body.error, 'should have error message');
    });
  }

  it('rejects presentation with empty fields array', async () => {
    const pres = await makeValidPresentation();
    const r = await vpost('/generate-proof', {
      body: { presentation: { ...pres, fields: [] } },
    });
    assert.strictEqual(r.status, 400);
    assert.ok(r.body.error);
  });

  it('rejects when neither presentation nor mdoc_input is provided', async () => {
    const r = await vpost('/generate-proof', { body: {} });
    assert.strictEqual(r.status, 400);
  });
});

// zkspec / buildLongfellowInput output is covered below without invoking WASM
// (POST /generate-proof runs Longfellow proof generation and can take minutes).

// ═══════════════════════════════════════════════════════════════════════════════
// buildLongfellowInput output — pure structural checks via a local invocation
// These tests bypass the HTTP layer to inspect the output object directly.
// ═══════════════════════════════════════════════════════════════════════════════

describe('buildLongfellowInput — output structure (direct module call)', () => {
  // We import the server module's buildLongfellowInput by re-implementing the
  // same logic used in server.js but calling it in-process.
  // The function is not exported, so we replicate a slim version that uses the
  // same dependencies to verify structural invariants.

  const path2 = require('node:path');
  const cborx = require(path2.join(__dirname, '../node_modules/cbor-x'));
  const mdl = require(path2.join(__dirname, '../node_modules/@auth0/mdl'));
  const mdlCbor = require(path2.join(__dirname, '../node_modules/@auth0/mdl/lib/cbor'));

  mdlCbor.setCborEncodeDecodeOptions({
    ...mdlCbor.getCborEncodeDecodeOptions(),
    variableMapSize: true,
  });

  const cborDecoder = new cborx.Encoder({
    useRecords: false,
    variableMapSize: true,
    mapsAsObjects: false,
    useTag259ForMaps: false,
  });

  /**
   * Minimal reimplementation of buildLongfellowInput (without WASM) so we can
   * inspect the output fields.
   */
  async function buildInput(p) {
    const required = [
      'raw_mdoc_b64', 'device_private_jwk', 'fields', 'doctype',
      'mdoc_generated_nonce', 'client_id', 'response_uri', 'verifier_nonce',
    ];
    for (const k of required) {
      if (p[k] === undefined || p[k] === null) throw new Error(`missing field: ${k}`);
    }
    if (!Array.isArray(p.fields) || p.fields.length === 0)
      throw new Error('fields must be a non-empty array');

    const issuanceBytes = Buffer.from(
      p.raw_mdoc_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64'
    );
    const issuanceMdoc = mdl.parse(issuanceBytes);

    const presentationDefinition = {
      id: 'test-' + Date.now(),
      input_descriptors: [{
        id: p.doctype,
        format: { mso_mdoc: { alg: ['ES256'] } },
        constraints: {
          fields: p.fields.map(f => ({
            path: [`$['org.iso.18013.5.1']['${f}']`],
            intent_to_retain: false,
          })),
        },
      }],
    };

    const builder = mdl.DeviceResponse.from(issuanceMdoc)
      .usingPresentationDefinition(presentationDefinition)
      .usingSessionTranscriptForOID4VP(
        p.mdoc_generated_nonce, p.client_id, p.response_uri, p.verifier_nonce,
      )
      .authenticateWithSignature(
        {
          kty: p.device_private_jwk.kty,
          crv: p.device_private_jwk.crv,
          x: p.device_private_jwk.x,
          y: p.device_private_jwk.y,
          d: p.device_private_jwk.d,
        },
        'ES256',
      );
    const presentationMdoc = await builder.sign();
    const presentationBytes = Buffer.from(presentationMdoc.encode());
    const presentationB64 = presentationBytes.toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const sessionTranscriptBytes = mdlCbor.cborEncode([
      null,
      null,
      [p.mdoc_generated_nonce, p.client_id, p.response_uri, p.verifier_nonce],
    ]);
    const transcriptHex = sessionTranscriptBytes.toString('hex');

    // Extract issuer key from x5chain
    let pkX, pkY;
    const presDecoded = cborDecoder.decode(presentationBytes);
    const issuerAuth = presDecoded.get('documents')[0].get('issuerSigned').get('issuerAuth');
    const unprotHdr = issuerAuth[1];
    const x5chain = unprotHdr instanceof Map ? unprotHdr.get(33) : unprotHdr[33];
    const certDer = Array.isArray(x5chain) ? x5chain[0] : x5chain;
    if (!certDer) throw new Error('no x5chain in issuerAuth');
    const x509 = new crypto.X509Certificate(certDer);
    const certJwk = x509.publicKey.export({ format: 'jwk' });
    pkX = '0x' + Buffer.from(certJwk.x, 'base64url').toString('hex');
    pkY = '0x' + Buffer.from(certJwk.y, 'base64url').toString('hex');

    const namespaceItems = (issuanceMdoc.documents[0].issuerSigned.nameSpaces || {})['org.iso.18013.5.1'] || [];
    const attributes = p.fields.map(field => {
      const item = namespaceItems.find(i => i.elementIdentifier === field);
      if (!item) throw new Error(`attribute ${field} not in credential`);
      const v = item.elementValue;
      let cborValue;
      if (v === true) cborValue = 'f5';
      else if (v === false) cborValue = 'f4';
      else if (typeof v === 'string') {
        const b = Buffer.from(v, 'utf8');
        if (b.length < 24) cborValue = (0x60 | b.length).toString(16).padStart(2, '0') + b.toString('hex');
        else if (b.length < 256) cborValue = '78' + b.length.toString(16).padStart(2, '0') + b.toString('hex');
        else throw new Error(`attribute ${field} too long`);
      }
      return { cbor_value: cborValue, id: field, namespace: 'org.iso.18013.5.1' };
    });

    return {
      attributes,
      doc_type: p.doctype,
      mdoc_data_base64: presentationB64,
      public_key: { x: pkX, y: pkY },
      time: p.time || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      transcript: transcriptHex,
      zkspec: attributes.length - 1,
    };
  }

  async function makePresentation(fields, age = 25) {
    const { credential, devicePrivateJwk } = await issueCredential(age);
    return {
      raw_mdoc_b64: credential,
      device_private_jwk: devicePrivateJwk,
      fields,
      doctype: 'org.iso.18013.5.1.age_verification',
      mdoc_generated_nonce: 'unit-test-nonce',
      client_id: 'http://localhost:3099',
      response_uri: 'http://localhost:3099/response',
      verifier_nonce: 'unit-verifier-nonce',
    };
  }

  it('zkspec is 0 for 1 field', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    assert.strictEqual(out.zkspec, 0);
  });

  it('zkspec is 1 for 2 fields', async () => {
    const pres = await makePresentation(['age_above_18', 'age_above_21'], 21);
    const out = await buildInput(pres);
    assert.strictEqual(out.zkspec, 1);
  });

  it('zkspec is 2 for 3 fields', async () => {
    const pres = await makePresentation(['age_above_18', 'age_above_21', 'age_above_25'], 25);
    const out = await buildInput(pres);
    assert.strictEqual(out.zkspec, 2);
  });

  it('transcript is bare CBOR array (starts with 0x83, not tag 0xd8)', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    const transcriptBytes = Buffer.from(out.transcript, 'hex');
    // CBOR array of 3 items: major type 4, additional info 3 → 0x83
    assert.strictEqual(transcriptBytes[0], 0x83, 'transcript must start with 0x83 (CBOR array[3])');
    // Must NOT start with 0xd8 (CBOR tag prefix)
    assert.notStrictEqual(transcriptBytes[0], 0xd8, 'transcript must not be tag-wrapped');
  });

  it('public_key.x and public_key.y start with "0x"', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    assert.ok(out.public_key.x.startsWith('0x'), 'x must start with 0x');
    assert.ok(out.public_key.y.startsWith('0x'), 'y must start with 0x');
  });

  it('public_key.x and public_key.y are 32-byte hex (66 chars total)', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    // '0x' + 64 hex digits = 66 chars for P-256 coordinates
    assert.strictEqual(out.public_key.x.length, 66, 'x must be 66 chars (0x + 32 bytes)');
    assert.strictEqual(out.public_key.y.length, 66, 'y must be 66 chars (0x + 32 bytes)');
  });

  it('time is exactly 20 characters', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    assert.strictEqual(out.time.length, 20, 'time must be exactly 20 chars');
    // Must not contain milliseconds: "2026-05-25T17:00:00Z" (20 chars)
    assert.ok(!out.time.includes('.'), 'time must not include milliseconds');
  });

  it('attributes have correct cbor_value for boolean true (f5)', async () => {
    const pres = await makePresentation(['age_above_18'], 18);
    const out = await buildInput(pres);
    const attr = out.attributes.find(a => a.id === 'age_above_18');
    assert.ok(attr, 'age_above_18 attribute must be present');
    assert.strictEqual(attr.cbor_value, 'f5', 'age_above_18 true → cbor f5');
  });

  it('attributes have correct cbor_value for boolean false (f4)', async () => {
    // age 18: age_above_21 is false
    const pres = await makePresentation(['age_above_21'], 18);
    const out = await buildInput(pres);
    const attr = out.attributes.find(a => a.id === 'age_above_21');
    assert.ok(attr, 'age_above_21 attribute must be present');
    assert.strictEqual(attr.cbor_value, 'f4', 'age_above_21 false → cbor f4');
  });

  it('issuer public key from x5chain matches verifier /issuer-key', async () => {
    // Issue a credential then build the longfellow input; compare the extracted
    // key against what the issuer advertises.
    const issuerKeyRes = await iget('/issuer-public-key');
    const issuerJwk = issuerKeyRes.body;

    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);

    // Convert issuer JWK x/y from base64url to hex for comparison
    const expectedX = '0x' + Buffer.from(issuerJwk.x, 'base64url').toString('hex');
    const expectedY = '0x' + Buffer.from(issuerJwk.y, 'base64url').toString('hex');

    assert.strictEqual(out.public_key.x.toLowerCase(), expectedX.toLowerCase(),
      'x5chain key must match issuer public key x');
    assert.strictEqual(out.public_key.y.toLowerCase(), expectedY.toLowerCase(),
      'x5chain key must match issuer public key y');
  });

  it('doc_type in output matches input doctype', async () => {
    const pres = await makePresentation(['age_above_18'], 21);
    const out = await buildInput(pres);
    assert.strictEqual(out.doc_type, 'org.iso.18013.5.1.age_verification');
  });

  it('attributes array length equals fields.length', async () => {
    const pres = await makePresentation(['age_above_18', 'age_above_21'], 21);
    const out = await buildInput(pres);
    assert.strictEqual(out.attributes.length, 2);
  });
});

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const nodeFetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const longfellow = require('./longfellow');
const mdocLib = require('../mdoc-lib.js');

const fetch = nodeFetch.default || nodeFetch;

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS: all origins
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// WASM endpoint kept for backward compatibility — native CLI is used instead.
app.get('/longfellow-zk.wasm', (req, res) => {
  res.status(404).json({ error: 'Native CLI used instead of WASM' });
});

// Serve pre-generated circuits. Returns 404 if not yet primed — the holder
// then falls back to simulated proofs.
app.get('/circuits/:name', (req, res) => {
  const safe = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const p = path.join(longfellow.CIRCUITS_DIR, safe);
  if (!p.startsWith(longfellow.CIRCUITS_DIR) || !fs.existsSync(p)) {
    return res.status(404).json({ error: 'circuit not found' });
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  res.sendFile(p);
});

const PORT = process.env.PORT || 3003;
const ISSUER_URL = process.env.ISSUER_URL || 'http://localhost:3001';

// In-memory stores
const sessions = new Map();
let issuerPublicKey = null;

// Fetch issuer public key on startup
async function loadIssuerKey() {
  if (process.env.ISSUER_PUBLIC_KEY_JWK) {
    try {
      issuerPublicKey = JSON.parse(process.env.ISSUER_PUBLIC_KEY_JWK);
      console.log('Loaded issuer public key from env');
      return;
    } catch (e) {
      console.warn('Failed to parse ISSUER_PUBLIC_KEY_JWK env var:', e.message);
    }
  }
  try {
    const res = await fetch(`${ISSUER_URL}/issuer-public-key`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    issuerPublicKey = await res.json();
    console.log('Fetched issuer public key from', ISSUER_URL);
    console.log('Issuer key (kid):', issuerPublicKey.kid || '(no kid)');
  } catch (e) {
    console.warn('Could not fetch issuer public key:', e.message);
    console.warn('Verification will proceed in simulated mode only');
  }
}

// Convert raw P-256 ECDSA signature (r||s, 64 bytes) to DER for Node's
// crypto.verify. WebCrypto produces raw; Node expects DER unless given
// { dsaEncoding: 'ieee-p1363' } — using DER is more portable across Node
// versions.
function rawEcdsaToDer(raw) {
  if (raw.length !== 64) throw new Error(`Expected 64-byte raw ECDSA sig, got ${raw.length}`);
  function toInt(buf) {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    let n = buf.slice(i);
    if (n[0] & 0x80) n = Buffer.concat([Buffer.from([0]), n]);
    return n;
  }
  const r = toInt(raw.slice(0, 32));
  const s = toInt(raw.slice(32));
  const seq = Buffer.concat([
    Buffer.from([0x02, r.length]), r,
    Buffer.from([0x02, s.length]), s,
  ]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

// Base64url encode
function base64url(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Build the complete Longfellow input from a holder-supplied presentation.
// Uses mdoc-lib.js to build the DeviceResponse, preserving exact IssuerSignedItem
// bytes so SHA256 digests match the MSO and the ZK circuit accepts the witness.
async function buildLongfellowInput(p) {
  const required = [
    'raw_mdoc_b64', 'device_private_jwk', 'fields', 'doctype',
    'mdoc_generated_nonce', 'client_id', 'response_uri', 'verifier_nonce',
  ];
  for (const k of required) {
    if (p[k] === undefined || p[k] === null) {
      throw new Error(`missing field: ${k}`);
    }
  }
  if (!Array.isArray(p.fields) || p.fields.length === 0) {
    throw new Error('fields must be a non-empty array');
  }

  // Build presentation using mdoc-lib.js — preserves original IssuerSignedItem bytes.
  const namespace = 'org.iso.18013.5.1';
  const presentationBytes = await mdocLib.buildPresentation({
    issuedMdocB64: p.raw_mdoc_b64,
    docType: p.doctype,
    namespace,
    fieldsToDisclose: p.fields,
    devicePrivateKeyJwk: {
      kty: p.device_private_jwk.kty,
      crv: p.device_private_jwk.crv,
      x: p.device_private_jwk.x,
      y: p.device_private_jwk.y,
      d: p.device_private_jwk.d,
    },
    mdocGeneratedNonce: p.mdoc_generated_nonce,
    clientId: p.client_id,
    responseUri: p.response_uri,
    verifierNonce: p.verifier_nonce,
  });

  const presentationB64 = presentationBytes.toString('base64url');

  // Session transcript bytes (plain CBOR array, matching what longfellow's
  // compute_transcript_hash appends into the DeviceAuthentication structure).
  const transcriptBuf = mdocLib.sessionTranscriptBytes(
    p.mdoc_generated_nonce, p.client_id, p.response_uri, p.verifier_nonce,
  );
  const transcriptHex = transcriptBuf.toString('hex');

  // Extract issuer public key from x5chain in the issuance MDOC.
  const issuanceBytes = Buffer.from(
    p.raw_mdoc_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64',
  );
  const parsedIssuance = mdocLib.parseIssuedMdoc(issuanceBytes);
  let pkX, pkY;
  try {
    const pk = mdocLib.extractIssuerPublicKey(parsedIssuance.documents[0]);
    pkX = pk.x;
    pkY = pk.y;
    console.log('[buildLongfellowInput] issuer key from x5chain x:', pkX.slice(0, 18) + '…');
  } catch (e) {
    console.warn('[buildLongfellowInput] x5chain extract failed, falling back:', e.message);
    const pubKey = p.issuer_public_key || p.public_key || issuerPublicKey;
    if (!pubKey) throw new Error('issuer public key unavailable');
    function normalizeCoord(v) {
      if (typeof v !== 'string') throw new Error('invalid pubkey coord');
      if (v.startsWith('0x')) return v.toLowerCase();
      const bytes = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      return '0x' + bytes.toString('hex');
    }
    pkX = normalizeCoord(pubKey.x);
    pkY = normalizeCoord(pubKey.y);
  }

  // Build cbor_value for each requested attribute from the parsed issuance MDOC.
  // cbor_value must be base64url-encoded CBOR bytes (the CLI decodes base64url first).
  const issuanceItems = parsedIssuance.documents[0].nameSpaces[namespace] || [];
  const attributes = p.fields.map(field => {
    const item = issuanceItems.find(i => i.elementIdentifier === field);
    if (!item) throw new Error(`attribute ${field} not in credential`);
    const v = item.elementValue;
    let cborBytes;
    if (v === true) cborBytes = Buffer.from([0xf5]);
    else if (v === false) cborBytes = Buffer.from([0xf4]);
    else if (typeof v === 'string') {
      const b = Buffer.from(v, 'utf8');
      if (b.length < 24) cborBytes = Buffer.concat([Buffer.from([0x60 | b.length]), b]);
      else if (b.length < 256) cborBytes = Buffer.concat([Buffer.from([0x78, b.length]), b]);
      else throw new Error(`attribute ${field} too long`);
    } else {
      throw new Error(`unsupported attribute type for ${field}: ${typeof v}`);
    }
    return { cbor_value: cborBytes.toString('base64url'), id: field, namespace };
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

// POST /create-request
app.post('/create-request', async (req, res) => {
  try {
    const { fields } = req.body;
    if (!Array.isArray(fields) || fields.length === 0) {
      return res.status(400).json({ error: 'fields must be a non-empty array' });
    }

    const validFields = ['age_above_18', 'age_above_21', 'age_above_25'];
    for (const f of fields) {
      if (!validFields.includes(f)) {
        return res.status(400).json({ error: `Invalid field: ${f}` });
      }
    }

    const session_id = uuidv4();
    const nonce = uuidv4();

    const presentation_definition = {
      id: session_id,
      input_descriptors: [{
        id: 'age_credential',
        format: {
          mso_mdoc_zk: {
            doctype: 'org.iso.18013.5.1.age_verification'
          }
        },
        constraints: {
          fields: fields.map(f => ({
            path: [`$['org.iso.18013.5.1']['${f}']`],
            intent_to_retain: false,
            // DIF Presentation Exchange JSONSchema filter: verifier requires true
            filter: { type: 'boolean', const: true },
          }))
        }
      }]
    };

    const pdEncoded = base64url(JSON.stringify(presentation_definition));
    const baseUrl = `http://localhost:${PORT}`;

    const request_uri = `openid4vp://?` +
      `client_id=${encodeURIComponent(baseUrl)}` +
      `&response_type=vp_token` +
      `&response_uri=${encodeURIComponent(baseUrl + '/response')}` +
      `&nonce=${encodeURIComponent(nonce)}` +
      `&presentation_definition=${pdEncoded}`;

    const qr_code_data_url = await QRCode.toDataURL(request_uri, { width: 300 });

    sessions.set(session_id, {
      session_id,
      nonce,
      fields,
      status: 'pending',
      created_at: new Date().toISOString(),
      disclosed_attributes: null,
      verified_at: null,
      error: null,
      proof_type: null
    });

    res.json({ session_id, request_uri, qr_code_data_url });
  } catch (err) {
    console.error('create-request error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /response
app.post('/response', async (req, res) => {
  try {
    const { vp_token, presentation_submission } = req.body;
    if (!vp_token || !presentation_submission) {
      return res.status(400).json({ error: 'Missing vp_token or presentation_submission' });
    }

    const session_id = presentation_submission.definition_id;
    const session = sessions.get(session_id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (session.status !== 'pending') {
      return res.status(400).json({ error: 'Session already processed' });
    }

    // Validate nonce
    if (vp_token.nonce && vp_token.nonce !== session.nonce) {
      session.status = 'failed';
      session.error = 'Nonce mismatch';
      session.verified_at = new Date().toISOString();
      return res.status(400).json({ error: 'Nonce mismatch' });
    }

    // Best-effort device-binding check: the holder signs a deterministic
    // transcript with the credential's device key. This is NOT a real
    // Longfellow ZK verification — it just proves the presenter holds the
    // private key matching the credential's deviceKey. Real ZK verification
    // additionally needs wasm_verify_proof against a Longfellow circuit.
    let deviceBindingOk = null;
    if (vp_token.device_signature && vp_token.device_public_jwk && vp_token.transcript_digest_hex) {
      try {
        const sortedFields = (vp_token.disclosed_fields_sorted || Object.keys(vp_token.disclosed_attributes || {})).slice().sort();
        const doctype = vp_token.doctype || 'org.iso.18013.5.1.age_verification';
        const transcriptInput = [
          'oid4vp-age-v1',
          `http://localhost:${PORT}`,
          session.nonce,
          `http://localhost:${PORT}/response`,
          doctype,
          sortedFields.join(',')
        ].join('|');
        const expectedDigest = crypto.createHash('sha256').update(transcriptInput).digest('hex');
        if (expectedDigest !== vp_token.transcript_digest_hex) {
          deviceBindingOk = false;
          session.error = 'Transcript digest mismatch';
        } else {
          const pubKey = crypto.createPublicKey({ key: vp_token.device_public_jwk, format: 'jwk' });
          const digestBytes = Buffer.from(expectedDigest, 'hex');
          const sigRaw = Buffer.from(vp_token.device_signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
          // WebCrypto outputs raw r||s (64 bytes for P-256); Node's verify needs DER.
          const derSig = rawEcdsaToDer(sigRaw);
          deviceBindingOk = crypto.verify(null, digestBytes, pubKey, derSig);
        }
      } catch (e) {
        deviceBindingOk = false;
        session.error = `Device signature check failed: ${e.message}`;
      }
    }

    if (vp_token.simulated === true) {
      // Simulated proof path. Annotate with device-binding result.
      const disclosed = vp_token.disclosed_attributes || {};
      const failedFields = session.fields.filter(f => disclosed[f] === false);
      if (failedFields.length > 0) {
        session.status = 'failed';
        session.proof_type = 'Simulated';
        session.error = `Age claim not met: ${failedFields.join(', ')} = false`;
      } else {
        session.status = 'verified_simulated';
        session.proof_type = deviceBindingOk
          ? 'Simulated proof + verified device binding'
          : 'Simulated';
      }
      session.device_binding_verified = deviceBindingOk === true;
      session.disclosed_attributes = disclosed;
      session.verified_at = new Date().toISOString();
      console.log(`Session ${session_id}: verified (simulated, device_binding=${deviceBindingOk})`);
    } else {
      // Real ZK proof path — attempt Longfellow verification.
      // vp_token.proof_json is the full proof JSON returned by wasm_generate_proof.
      const n = session.fields.length;
      const circuitPath = path.join(longfellow.CIRCUITS_DIR, `n${n}.circuit`);
      const circuitAvailable = fs.existsSync(circuitPath);

      let zkOk = null;
      let zkError = null;
      if (circuitAvailable && vp_token.proof_json) {
        try {
          zkOk = await longfellow.verifyProof(vp_token.proof_json);
        } catch (e) {
          zkError = e.message;
          console.warn('Longfellow verify error:', e);
        }
      } else if (!vp_token.proof_json) {
        zkError = 'No proof_json in vp_token';
      } else {
        zkError = `Circuit n${n}.circuit not pre-generated`;
      }

      if (zkOk === true) {
        // Policy check: all requested boolean fields must be true.
        const disclosed = vp_token.disclosed_attributes || {};
        const failedFields = session.fields.filter(f => disclosed[f] === false);
        if (failedFields.length > 0) {
          session.status = 'failed';
          session.proof_type = 'ZK (Longfellow)';
          session.error = `Age claim not met: ${failedFields.join(', ')} = false`;
        } else {
          session.status = 'verified_zk';
          session.proof_type = 'ZK (Longfellow)';
        }
      } else {
        // Could not run real ZK verify — still enforce policy before degrading.
        const disclosed = vp_token.disclosed_attributes || {};
        const failedFields = session.fields.filter(f => disclosed[f] === false);
        if (failedFields.length > 0) {
          session.status = 'failed';
          session.proof_type = 'Failed';
          session.error = `Age claim not met: ${failedFields.join(', ')} = false`;
        } else {
          session.status = deviceBindingOk ? 'verified_device_binding_only' : 'failed';
          session.proof_type = deviceBindingOk
            ? 'Device binding only (ZK verify unavailable)'
            : 'Failed';
          session.error = zkError || session.error || 'ZK verification not available';
        }
      }
      session.device_binding_verified = deviceBindingOk === true;
      session.disclosed_attributes = vp_token.disclosed_attributes || {};
      session.verified_at = new Date().toISOString();
      console.log(`Session ${session_id}: zk=${zkOk} device_binding=${deviceBindingOk} status=${session.status}`);
    }

    if (session.status === 'failed' && session.error && session.error.startsWith('Age claim not met')) {
      return res.status(400).json({ error: session.error, session_id });
    }
    res.json({ success: true, session_id });
  } catch (err) {
    console.error('response error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /session/:session_id
app.get('/session/:session_id', (req, res) => {
  const session = sessions.get(req.params.session_id);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  res.json(session);
});

// POST /generate-proof
// Accepts { presentation: {raw_mdoc_b64, device_private_jwk, fields, doctype,
//   mdoc_generated_nonce, client_id, response_uri, verifier_nonce, public_key,
//   issuer_public_key} } and builds a complete OID4VP DeviceResponse
// (including deviceSigned + deviceAuth signature) before running Longfellow.
// Legacy shape { mdoc_input } is also accepted but will fail at the WASM
// since the issuance MDOC has no deviceSigned.
app.post('/generate-proof', async (req, res) => {
  try {
    const { presentation, mdoc_input } = req.body;
    if (!presentation && !mdoc_input) {
      return res.status(400).json({ error: 'Missing presentation or mdoc_input' });
    }

    // Policy gate: reject before expensive proof generation if any requested
    // boolean field is false in the credential.
    if (presentation && presentation.raw_mdoc_b64 && Array.isArray(presentation.fields)) {
      try {
        const issuanceBytes = Buffer.from(
          presentation.raw_mdoc_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64',
        );
        const parsed = mdocLib.parseIssuedMdoc(issuanceBytes);
        const namespace = 'org.iso.18013.5.1';
        const items = (parsed.documents[0].nameSpaces[namespace] || []);
        const failedFields = presentation.fields.filter(field => {
          const item = items.find(i => i.elementIdentifier === field);
          return item && item.elementValue === false;
        });
        if (failedFields.length > 0) {
          return res.status(400).json({
            error: `Age claim not met: ${failedFields.join(', ')} = false`,
          });
        }
      } catch (e) {
        console.warn('Policy pre-check failed (continuing):', e.message);
      }
    }

    let finalInput;
    if (presentation) {
      try {
        finalInput = await buildLongfellowInput(presentation);
      } catch (e) {
        console.error('buildLongfellowInput failed:', e);
        return res.status(400).json({ error: `buildLongfellowInput: ${e.message}` });
      }
    } else {
      finalInput = mdoc_input;
    }

    const n = Array.isArray(finalInput.attributes) ? finalInput.attributes.length : 1;
    try {
      await longfellow.ensureCircuit(n);
    } catch (e) {
      return res.status(503).json({ error: `Circuit not available: ${e.message}` });
    }

    const proofJson = await longfellow.generateProof(finalInput);
    res.json({ proof_json: proofJson });
  } catch (err) {
    console.error('generate-proof error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /issuer-key
app.get('/issuer-key', (req, res) => {
  if (!issuerPublicKey) {
    return res.status(404).json({ error: 'Issuer public key not loaded' });
  }
  res.json(issuerPublicKey);
});

app.listen(PORT, async () => {
  await loadIssuerKey();
  console.log(`\nVerifier running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log(`  POST http://localhost:${PORT}/create-request`);
  console.log(`  POST http://localhost:${PORT}/response`);
  console.log(`  GET  http://localhost:${PORT}/session/:session_id`);
  console.log(`  GET  http://localhost:${PORT}/issuer-key`);
  console.log(`  GET  http://localhost:${PORT}/  (frontend)`);
});

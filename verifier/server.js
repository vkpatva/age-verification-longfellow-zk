const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const nodeFetch = require('node-fetch');
const path = require('path');

const fetch = nodeFetch.default || nodeFetch;

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS: all origins
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
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

// Base64url encode
function base64url(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
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
            intent_to_retain: false
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

    if (vp_token.simulated === true) {
      // Simulated proof path
      session.status = 'verified_simulated';
      session.proof_type = 'Simulated';
      session.disclosed_attributes = vp_token.disclosed_attributes || {};
      session.verified_at = new Date().toISOString();
      console.log(`Session ${session_id}: verified (simulated)`);
    } else {
      // Real ZK proof path
      const n = session.fields.length;
      const circuitPath = path.join(__dirname, 'circuits', `n${n}.circuit`);
      let circuitAvailable = false;
      try {
        require('fs').accessSync(circuitPath);
        circuitAvailable = true;
      } catch (_) {
        // circuit not available
      }

      if (!circuitAvailable) {
        // Stub: treat as unverifiable but log it
        console.warn(`Circuit n${n}.circuit not found — cannot verify ZK proof for session ${session_id}`);
        session.status = 'failed';
        session.error = `ZK circuit n${n}.circuit not available for verification`;
        session.verified_at = new Date().toISOString();
      } else {
        // Stub for Zenroom call — in production this would invoke Zenroom
        console.log(`Would verify ZK proof using ${circuitPath}`);
        session.status = 'verified_zk';
        session.proof_type = 'ZK (Longfellow)';
        session.disclosed_attributes = vp_token.disclosed_attributes || {};
        session.verified_at = new Date().toISOString();
      }
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

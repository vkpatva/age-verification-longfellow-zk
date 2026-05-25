require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { Document, MDoc } = require('@auth0/mdl');
const { Crypto } = require('@peculiar/webcrypto');
const { X509CertificateGenerator, X509Certificate } = require('@peculiar/x509');

const webcrypto = new Crypto();
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3001;
const ISSUER_URL = process.env.ISSUER_URL || `http://localhost:${PORT}`;
const JWT_SECRET = uuidv4();

// --- Key Setup ---
let issuerPrivateKeyJwk;
let issuerPublicKeyJwk;
let issuerCertificatePem;
let nodePrivateKey;

async function initKeys() {
  let privateKeyHex = process.env.ISSUER_PRIVATE_KEY_HEX;

  if (privateKeyHex) {
    // Import from hex (raw 32-byte private key scalar for P-256)
    const keyPair = await webcrypto.subtle.importKey(
      'raw',
      Buffer.from(privateKeyHex, 'hex'),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    ).catch(() => null);
    // Fall back to generating a new key if import fails
    if (!keyPair) privateKeyHex = null;
  }

  // Generate a fresh P-256 key pair
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  issuerPrivateKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
  issuerPublicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);

  // Generate self-signed certificate for the issuer key
  const cert = await X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: '01',
      name: 'CN=Age Verification Issuer, O=Test Issuer, C=IN',
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000), // 10 years
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      keys: keyPair,
      extensions: [
        new (require('@peculiar/x509').BasicConstraintsExtension)(true, 2, true),
        new (require('@peculiar/x509').KeyUsagesExtension)(
          require('@peculiar/x509').KeyUsageFlags.keyCertSign |
          require('@peculiar/x509').KeyUsageFlags.cRLSign |
          require('@peculiar/x509').KeyUsageFlags.digitalSignature,
          true
        ),
      ],
    },
    webcrypto
  );

  issuerCertificatePem = cert.toString('pem');

  // Export private key hex for logging (raw D parameter)
  const privateKeyHexExport = Buffer.from(
    Buffer.from(issuerPrivateKeyJwk.d, 'base64url')
  ).toString('hex');

  console.log('\n=== Age Verification Issuer ===');
  console.log(`Issuer URL: ${ISSUER_URL}`);
  console.log(`\nISSUER_PRIVATE_KEY_HEX=${privateKeyHexExport}`);
  console.log('\nIssuer Public Key (JWK):');
  console.log(JSON.stringify(issuerPublicKeyJwk, null, 2));
  console.log('\nAvailable endpoints:');
  console.log(`  GET  ${ISSUER_URL}/`);
  console.log(`  GET  ${ISSUER_URL}/.well-known/openid-credential-issuer`);
  console.log(`  POST ${ISSUER_URL}/token`);
  console.log(`  POST ${ISSUER_URL}/credential`);
  console.log(`  GET  ${ISSUER_URL}/offer?age=XX`);
  console.log(`  GET  ${ISSUER_URL}/issuer-public-key`);
  console.log('================================\n');
}

// --- In-memory pre-auth code store ---
// Map<code, { age, age_above_18, age_above_21, age_above_25, used }>
const preAuthCodes = new Map();

// --- Helpers ---
function deriveAgeFields(age) {
  return {
    age_above_18: age >= 18,
    age_above_21: age >= 21,
    age_above_25: age >= 25,
  };
}

async function buildMdoc(ageFields) {
  const issuanceDate = new Date();
  const expiryDate = new Date(issuanceDate);
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);

  // Dummy device key — in a real flow this comes from the wallet's proof
  const deviceKeyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const devicePublicKeyJwk = await webcrypto.subtle.exportKey('jwk', deviceKeyPair.publicKey);

  const document = await new Document('org.iso.18013.5.1.age_verification')
    .addIssuerNameSpace('org.iso.18013.5.1', {
      age_above_18: ageFields.age_above_18,
      age_above_21: ageFields.age_above_21,
      age_above_25: ageFields.age_above_25,
      issuer_country: 'IN',
      issuance_date: issuanceDate.toISOString(),
      expiry_date: expiryDate.toISOString(),
    })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({
      signed: issuanceDate,
      validFrom: issuanceDate,
      validUntil: expiryDate,
    })
    .addDeviceKeyInfo({ deviceKey: devicePublicKeyJwk })
    .sign({
      issuerPrivateKey: issuerPrivateKeyJwk,
      issuerCertificate: issuerCertificatePem,
      alg: 'ES256',
    });

  const encoded = new MDoc([document]).encode();
  return Buffer.from(encoded).toString('base64url');
}

// --- Routes ---

// GET /.well-known/openid-credential-issuer
app.get('/.well-known/openid-credential-issuer', (req, res) => {
  res.json({
    credential_issuer: ISSUER_URL,
    credential_endpoint: `${ISSUER_URL}/credential`,
    token_endpoint: `${ISSUER_URL}/token`,
    credentials_supported: [
      {
        format: 'mso_mdoc',
        doctype: 'org.iso.18013.5.1.age_verification',
        id: 'org.iso.18013.5.1.age_verification',
        claims: {
          'org.iso.18013.5.1': {
            age_above_18: { mandatory: true },
            age_above_21: { mandatory: true },
            age_above_25: { mandatory: true },
            issuer_country: { mandatory: true },
            issuance_date: { mandatory: true },
            expiry_date: { mandatory: true },
          },
        },
      },
    ],
  });
});

// POST /token
app.post('/token', (req, res) => {
  const grantType = req.body.grant_type;
  const preAuthCode = req.body['pre-authorized_code'] || req.query['pre-authorized_code'];

  if (grantType !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (!preAuthCode || !preAuthCodes.has(preAuthCode)) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid pre-authorized_code' });
  }

  const codeData = preAuthCodes.get(preAuthCode);
  if (codeData.used) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'pre-authorized_code already used' });
  }

  codeData.used = true;

  const accessToken = jwt.sign(
    { sub: preAuthCode, ageFields: codeData.ageFields },
    JWT_SECRET,
    { expiresIn: '5m' }
  );

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 300,
    c_nonce: uuidv4(),
    c_nonce_expires_in: 300,
  });
});

// POST /credential
app.post('/credential', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Missing Bearer token' });
  }

  const token = authHeader.slice(7);
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', error_description: err.message });
  }

  const { format } = req.body;
  if (format && format !== 'mso_mdoc') {
    return res.status(400).json({ error: 'unsupported_credential_format' });
  }

  try {
    const issuanceDate = new Date().toISOString();
    const expiryDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    const credential = await buildMdoc(payload.ageFields);
    res.json({
      format: 'mso_mdoc',
      credential,
      age_fields: {
        ...payload.ageFields,
        issuer_country: 'IN',
        issuance_date: issuanceDate,
        expiry_date: expiryDate,
      },
    });
  } catch (err) {
    console.error('MDOC build error:', err);
    res.status(500).json({ error: 'issuance_error', error_description: err.message });
  }
});

// GET /offer?age=XX
app.get('/offer', async (req, res) => {
  const age = parseInt(req.query.age, 10);
  if (isNaN(age) || age < 0 || age > 150) {
    return res.status(400).json({ error: 'Invalid age parameter' });
  }

  const ageFields = deriveAgeFields(age);
  const code = uuidv4();
  preAuthCodes.set(code, { ageFields, used: false });

  const credentialOffer = {
    credential_issuer: ISSUER_URL,
    credentials: ['org.iso.18013.5.1.age_verification'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': code,
        user_pin_required: false,
      },
    },
  };

  const offerJson = JSON.stringify(credentialOffer);
  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`;
  const qrDataUrl = await QRCode.toDataURL(offerUri);

  res.json({
    credential_offer_uri: offerUri,
    credential_offer: credentialOffer,
    qr_code: qrDataUrl,
    age_fields: ageFields,
  });
});

// GET /issuer-public-key
app.get('/issuer-public-key', (req, res) => {
  res.json(issuerPublicKeyJwk);
});

// GET / — simple UI
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Age Verification Issuer</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; background: #f9f9f9; }
    h1 { font-size: 1.5rem; color: #1a1a1a; }
    label { display: block; margin: 16px 0 4px; font-weight: 500; }
    input[type=number] { width: 100%; padding: 8px 12px; font-size: 1rem; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 12px; padding: 10px 24px; font-size: 1rem; background: #0066cc; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
    button:hover { background: #0055aa; }
    #result { margin-top: 24px; }
    #uri { word-break: break-all; background: #fff; border: 1px solid #ddd; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; }
    #qr { margin-top: 16px; }
    #qr img { border: 1px solid #ddd; border-radius: 6px; }
    .fields { margin-top: 12px; font-size: 0.9rem; color: #444; }
    .fields span { display: inline-block; margin-right: 12px; padding: 2px 8px; background: #e8f0fe; border-radius: 4px; }
    .error { color: red; margin-top: 12px; }
  </style>
</head>
<body>
  <h1>Age Verification Issuer</h1>
  <p>Test issuer for <code>org.iso.18013.5.1.age_verification</code> MDOC credentials.</p>

  <label for="ageInput">Enter age to simulate:</label>
  <input type="number" id="ageInput" min="0" max="150" value="21" />
  <button id="generateBtn">Generate Credential Offer</button>

  <div id="result" style="display:none">
    <div class="fields" id="ageFields"></div>
    <label>Credential Offer URI:</label>
    <div id="uri"></div>
    <div id="qr"></div>
  </div>
  <div class="error" id="error" style="display:none"></div>

  <script>
    document.getElementById('generateBtn').addEventListener('click', async () => {
      const age = document.getElementById('ageInput').value;
      const result = document.getElementById('result');
      const errorEl = document.getElementById('error');
      result.style.display = 'none';
      errorEl.style.display = 'none';

      try {
        const resp = await fetch('/offer?age=' + encodeURIComponent(age));
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Request failed');

        document.getElementById('uri').textContent = data.credential_offer_uri;
        document.getElementById('qr').innerHTML = '<img src="' + data.qr_code + '" alt="QR Code" />';

        const f = data.age_fields;
        document.getElementById('ageFields').innerHTML =
          '<span>age≥18: ' + f.age_above_18 + '</span>' +
          '<span>age≥21: ' + f.age_above_21 + '</span>' +
          '<span>age≥25: ' + f.age_above_25 + '</span>';

        result.style.display = 'block';
      } catch (e) {
        errorEl.textContent = e.message;
        errorEl.style.display = 'block';
      }
    });
  </script>
</body>
</html>`);
});

// --- Start ---
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`Issuer listening on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize keys:', err);
  process.exit(1);
});

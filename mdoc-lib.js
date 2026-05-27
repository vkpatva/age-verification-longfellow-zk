// Minimal MDOC implementation — no external MDOC libraries.
//
// Implements ISO 18013-5 MDOC issuance and presentation from scratch using
// only Node built-ins (crypto) and raw CBOR encoding.
//
// Exported functions:
//   issueCredential(opts)   → base64url-encoded DeviceResponse bytes (issuance)
//   buildPresentation(opts) → DeviceResponse bytes (Buffer) for ZK proving
//   parseIssuedMdoc(bytes)  → { documents: [{ docType, issuerSigned, deviceKeyInfo }] }
//   sessionTranscriptBytes(mdocGeneratedNonce, clientId, responseUri, verifierNonce) → Buffer

'use strict';

const crypto = require('crypto');

// ─── Raw CBOR encoder ────────────────────────────────────────────────────────

// Encode a uint into the smallest CBOR header for the given major type.
function hdr(majorType, n) {
  const mt = majorType << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) return Buffer.from([mt | 25, n >> 8, n & 0xff]);
  return Buffer.from([mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function encodeUint(n) {
  return hdr(0, n);
}

function encodeNint(n) {
  // n must be negative; encode as major type 1
  return hdr(1, -1 - n);
}

function encodeBstr(buf) {
  return Buffer.concat([hdr(2, buf.length), buf]);
}

function encodeStr(s) {
  const b = Buffer.from(s, 'utf8');
  return Buffer.concat([hdr(3, b.length), b]);
}

function encodeArray(items) {
  return Buffer.concat([hdr(4, items.length), ...items]);
}

function encodeMap(pairs) {
  // pairs: [[keyBuf, valBuf], ...]
  return Buffer.concat([hdr(5, pairs.length), ...pairs.map(([k, v]) => Buffer.concat([k, v]))]);
}

// CBOR tag(n)(value)
function encodeTag(tag, valueBuf) {
  return Buffer.concat([hdr(6, tag), valueBuf]);
}

// tag(24)(bstr(inner)) — the CBOR "embedded CBOR" pattern
function tag24(innerBuf) {
  return encodeTag(24, encodeBstr(innerBuf));
}

function encodeNull() { return Buffer.from([0xf6]); }
function encodeTrue() { return Buffer.from([0xf5]); }
function encodeFalse() { return Buffer.from([0xf4]); }

// Encode a JavaScript value to CBOR (limited type set used in MDOC).
function encode(v) {
  if (v === null || v === undefined) return encodeNull();
  if (v === true) return encodeTrue();
  if (v === false) return encodeFalse();
  if (typeof v === 'number') {
    if (Number.isInteger(v)) {
      return v >= 0 ? encodeUint(v) : encodeNint(v);
    }
    // float64
    const b = Buffer.allocUnsafe(9);
    b[0] = 0xfb;
    b.writeDoubleBE(v, 1);
    return b;
  }
  if (typeof v === 'string') return encodeStr(v);
  if (Buffer.isBuffer(v)) return encodeBstr(v);
  if (v instanceof Uint8Array) return encodeBstr(Buffer.from(v));
  if (v instanceof Date) {
    // tdate = tag(0)(str) — RFC 3339
    const s = v.toISOString().replace(/\.\d{3}Z$/, 'Z');
    return encodeTag(0, encodeStr(s));
  }
  if (Array.isArray(v)) return encodeArray(v.map(encode));
  if (v && typeof v === 'object' && v._cborTag !== undefined) {
    return encodeTag(v._cborTag, encode(v._value));
  }
  if (v instanceof Map) {
    return encodeMap([...v.entries()].map(([k, val]) => [encode(k), encode(val)]));
  }
  // plain object → CBOR map (string keys)
  const keys = Object.keys(v);
  return encodeMap(keys.map(k => [encodeStr(k), encode(v[k])]));
}

// ─── Raw CBOR decoder (only what we need for parsing issued MDOCs) ──────────

function decodeAll(buf, offset = 0) {
  const [v, next] = decodeOne(buf, offset);
  return [v, next];
}

function decodeOne(buf, pos) {
  const b = buf[pos];
  const mt = b >> 5;
  const ai = b & 0x1f;

  if (mt === 6) {
    // tag
    const [tagNum, afterTag] = readUintAi(buf, pos);
    const [val, after] = decodeOne(buf, afterTag);
    return [{ _cborTag: tagNum, _value: val, _rawPos: pos, _rawEnd: after }, after];
  }

  const [n, afterHdr] = readUintAi(buf, pos);

  switch (mt) {
    case 0: return [n, afterHdr]; // uint
    case 1: return [-1 - n, afterHdr]; // nint
    case 2: { // bstr
      const end = afterHdr + n;
      return [buf.slice(afterHdr, end), end];
    }
    case 3: { // str
      const end = afterHdr + n;
      return [buf.slice(afterHdr, end).toString('utf8'), end];
    }
    case 4: { // array
      if (ai === 31) {
        // indefinite — not expected in MDOC canonical encoding
        throw new Error('indefinite-length arrays not supported');
      }
      const items = [];
      let cur = afterHdr;
      for (let i = 0; i < n; i++) {
        const [item, next] = decodeOne(buf, cur);
        items.push(item);
        cur = next;
      }
      return [items, cur];
    }
    case 5: { // map
      if (ai === 31) throw new Error('indefinite-length maps not supported');
      const m = new Map();
      let cur = afterHdr;
      for (let i = 0; i < n; i++) {
        const [k, afterK] = decodeOne(buf, cur);
        const [v2, afterV] = decodeOne(buf, afterK);
        m.set(k, v2);
        cur = afterV;
      }
      return [m, cur];
    }
    case 7: {
      if (b === 0xf4) return [false, pos + 1];
      if (b === 0xf5) return [true, pos + 1];
      if (b === 0xf6) return [null, pos + 1];
      if (b === 0xfb) {
        const f = buf.readDoubleBE(pos + 1);
        return [f, pos + 9];
      }
      throw new Error(`Unhandled simple/float byte 0x${b.toString(16)}`);
    }
    default:
      throw new Error(`Unhandled CBOR major type ${mt}`);
  }
}

// Returns [value, nextOffset] where value is the uint encoded by the initial byte.
function readUintAi(buf, pos) {
  const b = buf[pos];
  const ai = b & 0x1f;
  if (ai < 24) return [ai, pos + 1];
  if (ai === 24) return [buf[pos + 1], pos + 2];
  if (ai === 25) return [(buf[pos + 1] << 8) | buf[pos + 2], pos + 3];
  if (ai === 26) return [((buf[pos + 1] << 24) | (buf[pos + 2] << 16) | (buf[pos + 3] << 8) | buf[pos + 4]) >>> 0, pos + 5];
  if (ai === 31) return [Infinity, pos + 1]; // indefinite
  throw new Error(`Unsupported additional info ${ai}`);
}

function decode(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const [v] = decodeOne(b, 0);
  return v;
}

// ─── COSE helpers ────────────────────────────────────────────────────────────

// COSE_Sign1 protected header for ES256: {1: -7}
const ES256_PROTECTED = encode(new Map([[1, -7]]));

// Sign a COSE_Sign1 structure.
// keyJwk: JWK with d (private key), x, y (P-256)
// payloadBytes: Buffer — the raw bytes to embed as the payload (will be bstr-wrapped)
// protHdrBytes: Buffer — pre-encoded protected header map bytes (will be bstr-wrapped)
// unprotHdrBuf: optional Buffer — pre-encoded unprotected header map (used as-is)
// Returns Buffer (the 4-element COSE_Sign1 array, CBOR-encoded as a bare array)
async function coseSign1(keyJwk, payloadBytes, protHdrBytes, unprotHdrBuf) {
  const prot = protHdrBytes || ES256_PROTECTED;
  // Sig_Structure = ["Signature1", bstr(protected), bstr(external_aad), bstr(payload)]
  const sigStruct = encodeArray([
    encodeStr('Signature1'),
    encodeBstr(prot),
    encodeBstr(Buffer.alloc(0)), // external AAD
    encodeBstr(payloadBytes),
  ]);

  const privKey = crypto.createPrivateKey({ key: keyJwk, format: 'jwk' });
  const derSig = crypto.sign(null, sigStruct, privKey);
  const rawSig = derToRaw(derSig);

  // COSE_Sign1: [bstr(protected), unprotected_map, bstr(payload), bstr(signature)]
  return encodeArray([
    encodeBstr(prot),
    unprotHdrBuf || encodeMap([]),
    encodeBstr(payloadBytes),
    encodeBstr(rawSig),
  ]);
}

// Convert DER-encoded ECDSA signature to raw r||s (64 bytes for P-256).
function derToRaw(der) {
  // DER: 30 <len> 02 <rlen> <r> 02 <slen> <s>
  let pos = 2; // skip 0x30 and total len
  if (der[1] & 0x80) pos += (der[1] & 0x7f); // long form length
  // r
  pos++; // 0x02
  const rLen = der[pos++];
  let r = der.slice(pos, pos + rLen);
  pos += rLen;
  // s
  pos++; // 0x02
  const sLen = der[pos++];
  let s = der.slice(pos, pos + sLen);

  // Strip leading zero bytes added for sign extension, pad to 32 bytes
  while (r.length > 32) r = r.slice(1);
  while (s.length > 32) s = s.slice(1);
  const raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length);
  s.copy(raw, 64 - s.length);
  return raw;
}

// ─── IssuerSignedItem encoding ───────────────────────────────────────────────

// Encode one IssuerSignedItem as its inner CBOR bytes (the bytes that get
// SHA-256'd for the MSO digest). Returns a Buffer.
//
// Key order must be: digestID, random, elementIdentifier, elementValue
// This is the canonical order Longfellow expects.
function encodeIssuerSignedItemInner(digestID, random16, elementIdentifier, elementValue) {
  return encodeMap([
    [encodeStr('digestID'), encodeUint(digestID)],
    [encodeStr('random'), encodeBstr(random16)],
    [encodeStr('elementIdentifier'), encodeStr(elementIdentifier)],
    [encodeStr('elementValue'), encode(elementValue)],
  ]);
}

// Encode the IssuerSignedItem as a CBOR bstr(tag24(innerBytes)) suitable
// for inclusion in the nameSpaces of an issued or presented MDOC.
function encodeIssuerSignedItemWrapper(digestID, random16, elementIdentifier, elementValue) {
  const inner = encodeIssuerSignedItemInner(digestID, random16, elementIdentifier, elementValue);
  return tag24(inner);
}

// ─── Session transcript ──────────────────────────────────────────────────────

// Encode the OID4VP session transcript as a plain CBOR array (no tag24 wrapper).
// This matches the format longfellow's compute_transcript_hash expects:
// it receives these raw bytes and builds the DeviceAuthentication CBOR around them.
function sessionTranscriptBytes(mdocGeneratedNonce, clientId, responseUri, verifierNonce) {
  return encode([null, null, [mdocGeneratedNonce, clientId, responseUri, verifierNonce]]);
}

// ─── Issuer credential building ──────────────────────────────────────────────

// Issue an MDOC credential.
//
// opts:
//   docType: string                              e.g. 'org.iso.18013.5.1.mDL'
//   namespace: string                            e.g. 'org.iso.18013.5.1'
//   attributes: { name: value, ... }             JS values
//   devicePublicKeyJwk: { kty, crv, x, y }      holder device key (public)
//   issuerPrivateKeyJwk: JWK with d              issuer signing key
//   issuerCertDer: Buffer                        DER-encoded X.509 cert
//
// Returns: base64url string of the DeviceResponse CBOR bytes.
async function issueCredential(opts) {
  const {
    docType, namespace, attributes,
    devicePublicKeyJwk, issuerPrivateKeyJwk, issuerCertDer,
  } = opts;

  const issuanceDate = new Date();
  const expiryDate = new Date(issuanceDate.getTime() + 365 * 24 * 3600 * 1000);

  // Build IssuerSignedItems — one per attribute, with sequential digestIDs.
  const attrNames = Object.keys(attributes);
  const items = attrNames.map((name, i) => {
    const random16 = crypto.randomBytes(16);
    const innerBytes = encodeIssuerSignedItemInner(i, random16, name, attributes[name]);
    const digest = crypto.createHash('sha256').update(innerBytes).digest();
    return { digestID: i, random16, name, value: attributes[name], innerBytes, digest };
  });

  // Build MSO
  const digestsMap = new Map(items.map(it => [it.digestID, it.digest]));
  const valueDigests = new Map([[namespace, digestsMap]]);

  // DeviceKey as COSE_Key: {1:2, -1:1, -2:bstr(x), -3:bstr(y)}
  const deviceKey = new Map([
    [1, 2],   // kty: EC2
    [-1, 1],  // crv: P-256
    [-2, Buffer.from(devicePublicKeyJwk.x, 'base64url')],
    [-3, Buffer.from(devicePublicKeyJwk.y, 'base64url')],
  ]);

  const mso = {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests: valueDigests,
    deviceKeyInfo: { deviceKey },
    docType,
    validityInfo: {
      signed: issuanceDate,
      validFrom: issuanceDate,
      validUntil: expiryDate,
    },
  };

  const msoBytes = encodeMso(mso);

  // COSE_Sign1 for issuerAuth
  // Per MDOC spec (ISO 18013-5): alg in protected header, x5chain in unprotected header.
  const protHdrBytes = encodeMap([
    [encodeUint(1), encode(-7)],    // alg: -7 = ES256
  ]);
  // Unprotected header: {33: bstr(certDer)}
  const unprotHdrBuf = encodeMap([
    [encodeUint(33), encodeBstr(issuerCertDer)],
  ]);
  // Payload = tag24(MSO_CBOR) — the standard MDOC COSE_Sign1 payload
  const issuerAuthBuf = await coseSign1(issuerPrivateKeyJwk, tag24(msoBytes), protHdrBytes, unprotHdrBuf);

  // nameSpaces: each item as tag24(bstr(inner))
  const nameSpaceItems = items.map(it => tag24(it.innerBytes));

  // Build the full DeviceResponse
  const issuerSigned = encodeMap([
    [encodeStr('nameSpaces'), encodeMap([[encodeStr(namespace), encodeArray(nameSpaceItems)]])],
    [encodeStr('issuerAuth'), issuerAuthBuf],
  ]);

  const document = encodeMap([
    [encodeStr('docType'), encodeStr(docType)],
    [encodeStr('issuerSigned'), issuerSigned],
  ]);

  const deviceResponse = encodeMap([
    [encodeStr('version'), encodeStr('1.0')],
    [encodeStr('documents'), encodeArray([document])],
    [encodeStr('status'), encodeUint(0)],
  ]);

  return deviceResponse.toString('base64url');
}

// Encode an MSO map to raw CBOR bytes (the inner map, no tag24 wrapper).
function encodeMso(mso) {
  const parts = [
    [encodeStr('version'), encodeStr(mso.version)],
    [encodeStr('digestAlgorithm'), encodeStr(mso.digestAlgorithm)],
    [encodeStr('valueDigests'), encodeValueDigests(mso.valueDigests)],
    [encodeStr('deviceKeyInfo'), encodeDeviceKeyInfo(mso.deviceKeyInfo)],
    [encodeStr('docType'), encodeStr(mso.docType)],
    [encodeStr('validityInfo'), encodeValidityInfo(mso.validityInfo)],
  ];
  return encodeMap(parts);
}

function encodeValueDigests(vd) {
  return encodeMap([...vd.entries()].map(([ns, digests]) => [
    encodeStr(ns),
    encodeMap([...digests.entries()].map(([id, digest]) => [
      encodeUint(id),
      encodeBstr(digest),
    ])),
  ]));
}

function encodeDeviceKeyInfo(dki) {
  return encodeMap([
    [encodeStr('deviceKey'), encodeCoseKey(dki.deviceKey)],
  ]);
}

function encodeCoseKey(key) {
  return encodeMap([...key.entries()].map(([k, v]) => [encode(k), encode(v)]));
}

function encodeValidityInfo(vi) {
  return encodeMap([
    [encodeStr('signed'), encode(vi.signed)],
    [encodeStr('validFrom'), encode(vi.validFrom)],
    [encodeStr('validUntil'), encode(vi.validUntil)],
  ]);
}

// ─── Presentation / DeviceResponse building ──────────────────────────────────

// Parse an issued MDOC (DeviceResponse bytes from issuer).
// Returns { version, documents: [{ docType, issuerSigned: { issuerAuth, nameSpaces }, issuerSignedItemBuffers }] }
function parseIssuedMdoc(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const dr = decode(buf);

  const documents = [];
  const rawDocs = dr.get('documents');
  for (const docRaw of rawDocs) {
    const docType = docRaw.get('docType');
    const issuerSigned = docRaw.get('issuerSigned');
    const nameSpacesRaw = issuerSigned.get('nameSpaces');
    const issuerAuthRaw = issuerSigned.get('issuerAuth');

    // Extract raw bytes for each IssuerSignedItem.
    // The MSO digest = SHA256(full tag24 bytes) = SHA256(d8 18 58 NN <inner>).
    // We preserve those full tag24 bytes in _rawTag24Bytes.
    const nameSpaces = {};
    for (const [ns, itemList] of nameSpacesRaw.entries()) {
      nameSpaces[ns] = [];
      for (const itemTag of itemList) {
        // itemTag is { _cborTag: 24, _value: bstrContent, _rawPos, _rawEnd }
        // _rawPos/_rawEnd index into buf — slice to get full tag24 bytes.
        const rawTag24Bytes = buf.slice(itemTag._rawPos, itemTag._rawEnd);
        // bstrContent is the bstr payload = the IssuerSignedItem CBOR map bytes.
        const bstrContent = Buffer.isBuffer(itemTag._value)
          ? itemTag._value : Buffer.from(itemTag._value);
        const innerDecoded = decode(bstrContent);
        nameSpaces[ns].push({
          _rawTag24Bytes: rawTag24Bytes,   // full d8 18 58 NN <inner> — for SHA256 digest
          _rawInnerBytes: bstrContent,     // IssuerSignedItem map bytes — for re-embedding
          digestID: innerDecoded.get('digestID'),
          random: innerDecoded.get('random'),
          elementIdentifier: innerDecoded.get('elementIdentifier'),
          elementValue: innerDecoded.get('elementValue'),
        });
      }
    }

    // Extract issuer cert from x5chain in issuerAuth unprotected header (per ISO 18013-5)
    let issuerCertDer = null;
    try {
      // issuerAuthRaw decoded CBOR array: [bstr(protected), Map(unprotected), bstr(payload), bstr(sig)]
      const unprotMap = issuerAuthRaw[1]; // Map
      if (unprotMap instanceof Map) {
        const x5chain = unprotMap.get(33);
        issuerCertDer = Buffer.isBuffer(x5chain) ? x5chain :
          (Array.isArray(x5chain) ? x5chain[0] : null);
      }
      // Fallback: some implementations put x5chain in protected header
      if (!issuerCertDer) {
        const protBstr = issuerAuthRaw[0];
        const protMap = decode(protBstr);
        if (protMap instanceof Map) {
          const x5chain = protMap.get(33);
          issuerCertDer = Buffer.isBuffer(x5chain) ? x5chain :
            (Array.isArray(x5chain) ? x5chain[0] : null);
        }
      }
    } catch (_) {}

    // Decode MSO from payload
    // issuerAuthRaw[2] is a Buffer: the bstr payload content = tag24(MSO_CBOR)
    let mso = null;
    try {
      const payloadBuf = issuerAuthRaw[2];
      // payloadBuf is the bstr content which is tag24(MSO_CBOR)
      // Decode: tag24 → _value = MSO_CBOR bytes
      const tagged = decode(payloadBuf);
      const msoCbor = (tagged && tagged._cborTag === 24) ? tagged._value : payloadBuf;
      mso = decode(msoCbor);
    } catch (e) { /* ignore parse errors */ }

    documents.push({
      docType,
      nameSpaces,
      issuerAuthRaw,   // preserve raw array for re-encoding
      issuerCertDer,
      mso,
    });
  }

  return { version: dr.get('version'), documents };
}

// Build a presentation DeviceResponse for ZK proving.
//
// opts:
//   issuedMdocB64: base64url string of the issued MDOC bytes
//   docType: string
//   namespace: string
//   fieldsToDisclose: [string, ...]       which elementIdentifiers to disclose
//   devicePrivateKeyJwk: JWK with d       holder's device signing key
//   mdocGeneratedNonce: string
//   clientId: string
//   responseUri: string
//   verifierNonce: string
//
// Returns: Buffer (the presentation DeviceResponse CBOR bytes)
async function buildPresentation(opts) {
  const {
    issuedMdocB64, docType, namespace, fieldsToDisclose,
    devicePrivateKeyJwk, mdocGeneratedNonce, clientId, responseUri, verifierNonce,
  } = opts;

  const issuanceBytes = Buffer.from(
    issuedMdocB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64'
  );
  const parsed = parseIssuedMdoc(issuanceBytes);
  const doc = parsed.documents[0];

  // Select only the requested IssuerSignedItems, preserving their original bytes.
  const allItems = doc.nameSpaces[namespace] || [];
  const disclosedItems = allItems.filter(it => fieldsToDisclose.includes(it.elementIdentifier));

  if (disclosedItems.length === 0) {
    throw new Error(`None of the requested fields found in namespace ${namespace}`);
  }

  // Build the session transcript bytes (plain CBOR array, no tag24 wrapper).
  const transcriptBuf = sessionTranscriptBytes(mdocGeneratedNonce, clientId, responseUri, verifierNonce);

  // Compute DeviceAuthentication bytes for signing:
  // DA = ["DeviceAuthentication", transcript_decoded, docType, tag24(bstr({}))]
  // auth0/mdl decodes the transcript bytes and re-encodes into the DA array.
  // Longfellow's compute_transcript_hash does the same: receives raw transcript bytes,
  // builds CBOR([DA_tag, transcript, docType, emptyNamespaces]).
  // The Sig_Structure payload = bstr(DA_bytes) where DA_bytes = bstr(tag24(DA_CBOR)).
  //
  // Actually: deviceAuthenticationBytes = bstr(tag24(["DeviceAuthentication", transcript, docType, tag24(bstr({}))]))
  // and the COSE Sig_Structure payload IS the deviceAuthenticationBytes (as a bstr).

  const emptyDeviceNamespaces = tag24(encodeMap([]));
  const daInner = encodeArray([
    encodeStr('DeviceAuthentication'),
    transcriptBuf,             // plain CBOR array bytes (decoded form goes here)
    encodeStr(docType),
    emptyDeviceNamespaces,
  ]);
  const deviceAuthBytes = tag24(daInner); // bstr(tag24(DA))

  // Sign with device key: COSE_Sign1 over deviceAuthBytes as the payload.
  const deviceSignatureBuf = await coseSign1(devicePrivateKeyJwk, deviceAuthBytes);

  // Re-encode the issuerAuth from the original raw decoded array.
  // The issuerAuth is [prot, unprot, payload, sig] — all already decoded to Buffers/Maps.
  const issuerAuthEncoded = reEncodeIssuerAuth(doc.issuerAuthRaw);

  // Encode nameSpaces with ONLY the disclosed items, using their original inner bytes.
  const nameSpaceItems = disclosedItems.map(it => tag24(it._rawInnerBytes));
  const nameSpacesEncoded = encodeMap([
    [encodeStr(namespace), encodeArray(nameSpaceItems)],
  ]);

  const issuerSigned = encodeMap([
    [encodeStr('nameSpaces'), nameSpacesEncoded],
    [encodeStr('issuerAuth'), issuerAuthEncoded],
  ]);

  // deviceSigned
  const deviceSigned = encodeMap([
    [encodeStr('nameSpaces'), tag24(encodeMap([]))],
    [encodeStr('deviceAuth'), encodeMap([
      [encodeStr('deviceSignature'), deviceSignatureBuf],
    ])],
  ]);

  const document = encodeMap([
    [encodeStr('docType'), encodeStr(docType)],
    [encodeStr('issuerSigned'), issuerSigned],
    [encodeStr('deviceSigned'), deviceSigned],
  ]);

  const deviceResponse = encodeMap([
    [encodeStr('version'), encodeStr('1.0')],
    [encodeStr('documents'), encodeArray([document])],
    [encodeStr('status'), encodeUint(0)],
  ]);

  return deviceResponse;
}

// Re-encode the issuerAuth COSE_Sign1 array from its decoded form.
// The issuerAuth was decoded by our parser into a JS array where:
//   [0] = Buffer (protected header bstr)
//   [1] = Map    (unprotected header)
//   [2] = Buffer (payload bstr — bstr(tag24(MSO)))
//   [3] = Buffer (signature bytes)
function reEncodeIssuerAuth(raw) {
  // raw is a JS array from our decoder
  if (!Array.isArray(raw) || raw.length !== 4) {
    throw new Error('Invalid issuerAuth: expected 4-element array');
  }
  const [prot, unprot, payload, sig] = raw;

  // prot is already a Buffer (the raw bstr bytes of the protected header)
  const protBuf = Buffer.isBuffer(prot) ? prot : Buffer.from(prot);

  // unprot is a Map (unprotected header) — re-encode it
  // For issuer: unprotected header may contain x5chain (label 33) or kid
  const unprotEncoded = encodeUnprotectedHeader(unprot);

  // payload is a Buffer (the bstr content, i.e. bstr(tag24(MSO)))
  const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);

  // sig is a Buffer
  const sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(sig);

  return encodeArray([
    encodeBstr(protBuf),
    unprotEncoded,
    encodeBstr(payloadBuf),
    encodeBstr(sigBuf),
  ]);
}

function encodeUnprotectedHeader(h) {
  if (h instanceof Map) {
    const pairs = [];
    for (const [k, v] of h.entries()) {
      const kEnc = typeof k === 'number' ? (k >= 0 ? encodeUint(k) : encodeNint(k)) : encodeStr(k);
      let vEnc;
      if (Buffer.isBuffer(v)) vEnc = encodeBstr(v);
      else if (Array.isArray(v)) vEnc = encodeArray(v.map(x => Buffer.isBuffer(x) ? encodeBstr(x) : encode(x)));
      else vEnc = encode(v);
      pairs.push([kEnc, vEnc]);
    }
    return encodeMap(pairs);
  }
  return encodeMap([]);
}

// ─── Parse issued MDOC from issuerAuth to extract public key ────────────────

// Extract issuer public key (x, y as hex with 0x prefix) from parsed doc.
function extractIssuerPublicKey(parsedDoc) {
  if (!parsedDoc.issuerCertDer) throw new Error('No x5chain in issuerAuth');
  const x509 = new crypto.X509Certificate(parsedDoc.issuerCertDer);
  const jwk = x509.publicKey.export({ format: 'jwk' });
  return {
    x: '0x' + Buffer.from(jwk.x, 'base64url').toString('hex'),
    y: '0x' + Buffer.from(jwk.y, 'base64url').toString('hex'),
  };
}

module.exports = {
  // Encoding primitives (exported for tests / server.js)
  encode, decode, tag24, encodeBstr, encodeStr, encodeMap, encodeArray, encodeUint, encodeNint,
  encodeIssuerSignedItemInner, encodeIssuerSignedItemWrapper,
  sessionTranscriptBytes,

  // Main API
  issueCredential,
  parseIssuedMdoc,
  buildPresentation,
  extractIssuerPublicKey,
};

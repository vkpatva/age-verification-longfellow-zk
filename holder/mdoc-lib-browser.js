// Browser port of mdoc-lib.js + buildLongfellowInput from verifier/server.js.
//
// Uses Uint8Array instead of Node Buffer and WebCrypto instead of require('crypto').
// No external dependencies — embeds directly in the holder HTML page.
//
// Exports (as window.MdocLib):
//   parseIssuedMdoc(bytes: Uint8Array) → { documents }
//   buildPresentation(opts) → Promise<Uint8Array>
//   sessionTranscriptBytes(...) → Uint8Array
//   extractIssuerPublicKey(parsedDoc) → Promise<{ x: "0x...", y: "0x..." }>
//   buildLongfellowInput(presentation) → Promise<object>   ← the key one

(function(global) {
'use strict';

// ─── Uint8Array helpers (replace Node Buffer) ────────────────────────────────

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function fromUtf8(s) {
  return new TextEncoder().encode(s);
}

function toUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function isBytes(v) { return v instanceof Uint8Array; }

// ─── Raw CBOR encoder ────────────────────────────────────────────────────────

function hdr(majorType, n) {
  const mt = majorType << 5;
  if (n < 24) return new Uint8Array([mt | n]);
  if (n < 0x100) return new Uint8Array([mt | 24, n]);
  if (n < 0x10000) return new Uint8Array([mt | 25, n >> 8, n & 0xff]);
  return new Uint8Array([mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function encodeUint(n) { return hdr(0, n); }
function encodeNint(n) { return hdr(1, -1 - n); }

function encodeBstr(bytes) {
  return concat(hdr(2, bytes.length), bytes);
}

function encodeStr(s) {
  const b = fromUtf8(s);
  return concat(hdr(3, b.length), b);
}

function encodeArray(items) {
  return concat(hdr(4, items.length), ...items);
}

function encodeMap(pairs) {
  return concat(hdr(5, pairs.length), ...pairs.map(([k, v]) => concat(k, v)));
}

function encodeTag(tag, valueBuf) {
  return concat(hdr(6, tag), valueBuf);
}

function tag24(innerBuf) {
  return encodeTag(24, encodeBstr(innerBuf));
}

function encodeNull() { return new Uint8Array([0xf6]); }
function encodeTrue() { return new Uint8Array([0xf5]); }
function encodeFalse() { return new Uint8Array([0xf4]); }

function encode(v) {
  if (v === null || v === undefined) return encodeNull();
  if (v === true) return encodeTrue();
  if (v === false) return encodeFalse();
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return v >= 0 ? encodeUint(v) : encodeNint(v);
    // float64
    const b = new Uint8Array(9);
    b[0] = 0xfb;
    const view = new DataView(b.buffer);
    view.setFloat64(1, v, false);
    return b;
  }
  if (typeof v === 'string') return encodeStr(v);
  if (isBytes(v)) return encodeBstr(v);
  if (v instanceof Date) {
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
  const keys = Object.keys(v);
  return encodeMap(keys.map(k => [encodeStr(k), encode(v[k])]));
}

// ─── Raw CBOR decoder ────────────────────────────────────────────────────────

function readUintAi(buf, pos) {
  const b = buf[pos];
  const ai = b & 0x1f;
  if (ai < 24) return [ai, pos + 1];
  if (ai === 24) return [buf[pos + 1], pos + 2];
  if (ai === 25) return [(buf[pos + 1] << 8) | buf[pos + 2], pos + 3];
  if (ai === 26) {
    const v = ((buf[pos+1] << 24) | (buf[pos+2] << 16) | (buf[pos+3] << 8) | buf[pos+4]) >>> 0;
    return [v, pos + 5];
  }
  if (ai === 31) return [Infinity, pos + 1];
  throw new Error(`Unsupported additional info ${ai}`);
}

function decodeOne(buf, pos) {
  const b = buf[pos];
  const mt = b >> 5;

  if (mt === 6) {
    const [tagNum, afterTag] = readUintAi(buf, pos);
    const [val, after] = decodeOne(buf, afterTag);
    return [{ _cborTag: tagNum, _value: val, _rawPos: pos, _rawEnd: after }, after];
  }

  const [n, afterHdr] = readUintAi(buf, pos);

  switch (mt) {
    case 0: return [n, afterHdr];
    case 1: return [-1 - n, afterHdr];
    case 2: return [buf.slice(afterHdr, afterHdr + n), afterHdr + n];
    case 3: return [toUtf8(buf.slice(afterHdr, afterHdr + n)), afterHdr + n];
    case 4: {
      const items = [];
      let cur = afterHdr;
      for (let i = 0; i < n; i++) {
        const [item, next] = decodeOne(buf, cur);
        items.push(item);
        cur = next;
      }
      return [items, cur];
    }
    case 5: {
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
        const view = new DataView(buf.buffer, buf.byteOffset + pos + 1, 8);
        return [view.getFloat64(0, false), pos + 9];
      }
      throw new Error(`Unhandled simple/float 0x${b.toString(16)}`);
    }
    default:
      throw new Error(`Unhandled CBOR major type ${mt}`);
  }
}

function decode(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const [v] = decodeOne(buf, 0);
  return v;
}

// ─── COSE / ECDSA helpers ────────────────────────────────────────────────────

// DER → raw r||s (64 bytes)
function derToRaw(der) {
  let pos = 2;
  if (der[1] & 0x80) pos += (der[1] & 0x7f);
  pos++; // 0x02
  const rLen = der[pos++];
  let r = der.slice(pos, pos + rLen); pos += rLen;
  pos++; // 0x02
  const sLen = der[pos++];
  let s = der.slice(pos, pos + sLen);
  while (r.length > 32) r = r.slice(1);
  while (s.length > 32) s = s.slice(1);
  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

// Sign a COSE_Sign1 using WebCrypto ECDSA P-256 / SHA-256.
async function coseSign1(privateJwk, payloadBytes, protHdrBytes, unprotHdrBuf) {
  const prot = protHdrBytes || encode(new Map([[1, -7]]));
  const sigStruct = encodeArray([
    encodeStr('Signature1'),
    encodeBstr(prot),
    encodeBstr(new Uint8Array(0)),
    encodeBstr(payloadBytes),
  ]);

  const key = await crypto.subtle.importKey(
    'jwk', privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
  const sigRaw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, sigStruct)
  );

  return encodeArray([
    encodeBstr(prot),
    unprotHdrBuf || encodeMap([]),
    encodeBstr(payloadBytes),
    encodeBstr(sigRaw),
  ]);
}

// ─── IssuerSignedItem / session transcript ───────────────────────────────────

function encodeIssuerSignedItemInner(digestID, random16, elementIdentifier, elementValue) {
  return encodeMap([
    [encodeStr('digestID'), encodeUint(digestID)],
    [encodeStr('random'), encodeBstr(random16)],
    [encodeStr('elementIdentifier'), encodeStr(elementIdentifier)],
    [encodeStr('elementValue'), encode(elementValue)],
  ]);
}

function sessionTranscriptBytes(mdocGeneratedNonce, clientId, responseUri, verifierNonce) {
  return encode([null, null, [mdocGeneratedNonce, clientId, responseUri, verifierNonce]]);
}

// ─── Parse issued MDOC ───────────────────────────────────────────────────────

function parseIssuedMdoc(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const dr = decode(buf);

  const documents = [];
  const rawDocs = dr.get('documents');
  for (const docRaw of rawDocs) {
    const docType = docRaw.get('docType');
    const issuerSigned = docRaw.get('issuerSigned');
    const nameSpacesRaw = issuerSigned.get('nameSpaces');
    const issuerAuthRaw = issuerSigned.get('issuerAuth');

    const nameSpaces = {};
    for (const [ns, itemList] of nameSpacesRaw.entries()) {
      nameSpaces[ns] = [];
      for (const itemTag of itemList) {
        const rawTag24Bytes = buf.slice(itemTag._rawPos, itemTag._rawEnd);
        const bstrContent = itemTag._value instanceof Uint8Array
          ? itemTag._value : new Uint8Array(itemTag._value);
        const innerDecoded = decode(bstrContent);
        nameSpaces[ns].push({
          _rawTag24Bytes: rawTag24Bytes,
          _rawInnerBytes: bstrContent,
          digestID: innerDecoded.get('digestID'),
          random: innerDecoded.get('random'),
          elementIdentifier: innerDecoded.get('elementIdentifier'),
          elementValue: innerDecoded.get('elementValue'),
        });
      }
    }

    // Extract issuer cert from x5chain (unprotected header label 33)
    let issuerCertDer = null;
    try {
      const unprotMap = issuerAuthRaw[1];
      if (unprotMap instanceof Map) {
        const x5chain = unprotMap.get(33);
        issuerCertDer = x5chain instanceof Uint8Array ? x5chain
          : (Array.isArray(x5chain) ? x5chain[0] : null);
      }
      if (!issuerCertDer) {
        const protBstr = issuerAuthRaw[0];
        const protMap = decode(protBstr);
        if (protMap instanceof Map) {
          const x5chain = protMap.get(33);
          issuerCertDer = x5chain instanceof Uint8Array ? x5chain
            : (Array.isArray(x5chain) ? x5chain[0] : null);
        }
      }
    } catch (_) {}

    // Decode MSO
    let mso = null;
    try {
      const payloadBuf = issuerAuthRaw[2];
      const tagged = decode(payloadBuf);
      const msoCbor = (tagged && tagged._cborTag === 24) ? tagged._value : payloadBuf;
      mso = decode(msoCbor);
    } catch (_) {}

    documents.push({ docType, nameSpaces, issuerAuthRaw, issuerCertDer, mso });
  }

  return { version: dr.get('version'), documents };
}

// ─── Extract issuer public key from DER X.509 cert ──────────────────────────
// WebCrypto can't parse raw DER X.509 directly, but SubtleCrypto can import
// a SubjectPublicKeyInfo (SPKI) which is a subset of the cert.
// We locate the EC public key bit string in the DER manually.

function extractSpkiFromCert(derBytes) {
  // Walk the DER to find the subjectPublicKeyInfo sequence.
  // DER structure: SEQUENCE { tbsCertificate SEQUENCE { ... subjectPublicKeyInfo SEQUENCE { ... } } }
  // We do a minimal parse: find the AlgorithmIdentifier for EC key (OID 1.2.840.10045.2.1)
  // and return the SubjectPublicKeyInfo SEQUENCE containing it.
  const EC_OID = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // 1.2.840.10045.2.1

  function tlvLen(buf, pos) {
    if (buf[pos] < 0x80) return [buf[pos], pos + 1];
    const lenBytes = buf[pos] & 0x7f;
    let len = 0;
    for (let i = 0; i < lenBytes; i++) len = (len << 8) | buf[pos + 1 + i];
    return [len, pos + 1 + lenBytes];
  }

  function findOid(buf, start, end) {
    for (let i = start; i < end - EC_OID.length; i++) {
      if (buf[i] === 0x06 && buf[i + 1] === EC_OID.length) {
        let match = true;
        for (let j = 0; j < EC_OID.length; j++) {
          if (buf[i + 2 + j] !== EC_OID[j]) { match = false; break; }
        }
        if (match) return i;
      }
    }
    return -1;
  }

  const buf = derBytes;
  const oidPos = findOid(buf, 0, buf.length);
  if (oidPos < 0) throw new Error('EC OID not found in cert DER');

  // Walk back to find the enclosing SEQUENCE (subjectPublicKeyInfo)
  // The SPKI SEQUENCE starts a few bytes before the OID.
  // Pattern: 30 <len> 30 <len> 06 07 <ec-oid> ...
  // Scan backward for 0x30 that encloses the OID position.
  let spkiStart = -1;
  for (let i = oidPos - 1; i >= 0; i--) {
    if (buf[i] === 0x30) {
      const [len, contentStart] = tlvLen(buf, i + 1);
      if (contentStart + len >= oidPos + EC_OID.length + 2) {
        // Check if this SEQUENCE contains the AlgorithmIdentifier with our OID
        if (buf[contentStart] === 0x30) {
          spkiStart = i;
          break;
        }
      }
    }
  }
  if (spkiStart < 0) throw new Error('SubjectPublicKeyInfo not found');

  const [spkiLen, spkiContent] = tlvLen(buf, spkiStart + 1);
  return buf.slice(spkiStart, spkiContent + spkiLen);
}

async function extractIssuerPublicKey(parsedDoc) {
  if (!parsedDoc.issuerCertDer) throw new Error('No x5chain in issuerAuth');
  const certDer = parsedDoc.issuerCertDer;
  const spki = extractSpkiFromCert(certDer);

  const key = await crypto.subtle.importKey(
    'spki', spki,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return {
    x: '0x' + toHex(b64urlToBytes(jwk.x)),
    y: '0x' + toHex(b64urlToBytes(jwk.y)),
  };
}

// ─── Re-encode issuerAuth ────────────────────────────────────────────────────

function encodeUnprotectedHeader(h) {
  if (!(h instanceof Map)) return encodeMap([]);
  const pairs = [];
  for (const [k, v] of h.entries()) {
    const kEnc = typeof k === 'number'
      ? (k >= 0 ? encodeUint(k) : encodeNint(k))
      : encodeStr(k);
    let vEnc;
    if (isBytes(v)) vEnc = encodeBstr(v);
    else if (Array.isArray(v)) vEnc = encodeArray(v.map(x => isBytes(x) ? encodeBstr(x) : encode(x)));
    else vEnc = encode(v);
    pairs.push([kEnc, vEnc]);
  }
  return encodeMap(pairs);
}

function reEncodeIssuerAuth(raw) {
  if (!Array.isArray(raw) || raw.length !== 4)
    throw new Error('Invalid issuerAuth: expected 4-element array');
  const [prot, unprot, payload, sig] = raw;
  return encodeArray([
    encodeBstr(prot instanceof Uint8Array ? prot : new Uint8Array(prot)),
    encodeUnprotectedHeader(unprot),
    encodeBstr(payload instanceof Uint8Array ? payload : new Uint8Array(payload)),
    encodeBstr(sig instanceof Uint8Array ? sig : new Uint8Array(sig)),
  ]);
}

// ─── Build presentation DeviceResponse ──────────────────────────────────────

async function buildPresentation(opts) {
  const {
    issuedMdocB64, docType, namespace, fieldsToDisclose,
    devicePrivateKeyJwk, mdocGeneratedNonce, clientId, responseUri, verifierNonce,
  } = opts;

  const issuanceBytes = b64urlToBytes(issuedMdocB64);
  const parsed = parseIssuedMdoc(issuanceBytes);
  const doc = parsed.documents[0];

  const allItems = doc.nameSpaces[namespace] || [];
  const disclosedItems = allItems.filter(it => fieldsToDisclose.includes(it.elementIdentifier));
  if (disclosedItems.length === 0)
    throw new Error(`None of the requested fields found in namespace ${namespace}`);

  const transcriptBuf = sessionTranscriptBytes(mdocGeneratedNonce, clientId, responseUri, verifierNonce);

  const emptyDeviceNamespaces = tag24(encodeMap([]));
  const daInner = encodeArray([
    encodeStr('DeviceAuthentication'),
    transcriptBuf,
    encodeStr(docType),
    emptyDeviceNamespaces,
  ]);
  const deviceAuthBytes = tag24(daInner);

  const deviceSignatureBuf = await coseSign1(devicePrivateKeyJwk, deviceAuthBytes);
  const issuerAuthEncoded = reEncodeIssuerAuth(doc.issuerAuthRaw);

  const nameSpaceItems = disclosedItems.map(it => tag24(it._rawInnerBytes));
  const nameSpacesEncoded = encodeMap([
    [encodeStr(namespace), encodeArray(nameSpaceItems)],
  ]);

  const issuerSigned = encodeMap([
    [encodeStr('nameSpaces'), nameSpacesEncoded],
    [encodeStr('issuerAuth'), issuerAuthEncoded],
  ]);

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

  return encodeMap([
    [encodeStr('version'), encodeStr('1.0')],
    [encodeStr('documents'), encodeArray([document])],
    [encodeStr('status'), encodeUint(0)],
  ]);
}

// ─── buildLongfellowInput ────────────────────────────────────────────────────
// Browser equivalent of server.js buildLongfellowInput.
// Takes the same `presentation` object the holder sends to /generate-proof
// and returns the mdocInput JSON object for the WASM prover.

async function buildLongfellowInput(p) {
  const required = [
    'raw_mdoc_b64', 'device_private_jwk', 'fields', 'doctype',
    'mdoc_generated_nonce', 'client_id', 'response_uri', 'verifier_nonce',
  ];
  for (const k of required) {
    if (p[k] === undefined || p[k] === null)
      throw new Error(`missing field: ${k}`);
  }
  if (!Array.isArray(p.fields) || p.fields.length === 0)
    throw new Error('fields must be a non-empty array');

  const namespace = 'org.iso.18013.5.1';

  const presentationBytes = await buildPresentation({
    issuedMdocB64: p.raw_mdoc_b64,
    docType: p.doctype,
    namespace,
    fieldsToDisclose: p.fields,
    devicePrivateKeyJwk: p.device_private_jwk,
    mdocGeneratedNonce: p.mdoc_generated_nonce,
    clientId: p.client_id,
    responseUri: p.response_uri,
    verifierNonce: p.verifier_nonce,
  });

  const presentationB64 = bytesToB64url(presentationBytes);

  const transcriptBuf = sessionTranscriptBytes(
    p.mdoc_generated_nonce, p.client_id, p.response_uri, p.verifier_nonce,
  );
  const transcriptHex = toHex(transcriptBuf);

  // Extract issuer public key from x5chain
  const issuanceBytes = b64urlToBytes(p.raw_mdoc_b64);
  const parsedIssuance = parseIssuedMdoc(issuanceBytes);
  let pkX, pkY;
  try {
    const pk = await extractIssuerPublicKey(parsedIssuance.documents[0]);
    pkX = pk.x;
    pkY = pk.y;
  } catch (e) {
    throw new Error(`Could not extract issuer public key from x5chain: ${e.message}`);
  }

  // Build cbor_value for each attribute (base64url-encoded CBOR bytes)
  const issuanceItems = parsedIssuance.documents[0].nameSpaces[namespace] || [];
  const attributes = p.fields.map(field => {
    const item = issuanceItems.find(i => i.elementIdentifier === field);
    if (!item) throw new Error(`attribute ${field} not in credential`);
    const v = item.elementValue;
    let cborBytes;
    if (v === true) cborBytes = new Uint8Array([0xf5]);
    else if (v === false) cborBytes = new Uint8Array([0xf4]);
    else if (typeof v === 'string') {
      const b = fromUtf8(v);
      if (b.length < 24) cborBytes = concat(new Uint8Array([0x60 | b.length]), b);
      else if (b.length < 256) cborBytes = concat(new Uint8Array([0x78, b.length]), b);
      else throw new Error(`attribute ${field} too long`);
    } else {
      throw new Error(`unsupported attribute type for ${field}: ${typeof v}`);
    }
    return { cbor_value: bytesToB64url(cborBytes), id: field, namespace };
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

// ─── WASM prover interface ───────────────────────────────────────────────────
// Calls the longfellow WASM module (must be loaded as window.LongfellowModule).
// circuitBytes: Uint8Array of raw circuit bytes (NOT the JSON wrapper)
// mdocInput: the object from buildLongfellowInput
// Returns: { proof_data_base64, public_key, transcript, time, doc_type, zkspec, attributes, mdoc_data_base64 }

async function wasmGenerateProof(Module, circuitBytes, mdocInput) {
  const { _lf_prove_direct, _lf_free, _lf_malloc, HEAPU8, getValue } = Module;

  // Encode all string/buffer args into WASM linear memory
  function writeBytes(bytes) {
    const ptr = _lf_malloc(bytes.length);
    HEAPU8.set(bytes, ptr);
    return ptr;
  }

  function writeStr(s) {
    const bytes = fromUtf8(s + '\0');
    return writeBytes(bytes);
  }

  // RequestedAttribute layout from mdoc_zk.h:
  //   uint8_t namespace_id[64]   @ 0
  //   uint8_t id[32]             @ 64
  //   uint8_t cbor_value[64]     @ 96
  //   size_t namespace_len       @ 160
  //   size_t id_len              @ 164/168
  //   size_t cbor_value_len      @ 168/176
  // Total: 160 + 3*sizeof(size_t). On WASM32 size_t=4 → total = 172 bytes
  const RA_SIZE = 172;
  const n = mdocInput.attributes.length;
  const attrsPtr = _lf_malloc(RA_SIZE * n);

  for (let i = 0; i < n; i++) {
    const attr = mdocInput.attributes[i];
    const base = attrsPtr + i * RA_SIZE;

    const nsBytes = fromUtf8(attr.namespace);
    const idBytes = fromUtf8(attr.id);
    const cborBytes = b64urlToBytes(attr.cbor_value);

    HEAPU8.fill(0, base, base + RA_SIZE);
    HEAPU8.set(nsBytes.slice(0, 64), base);
    HEAPU8.set(idBytes.slice(0, 32), base + 64);
    HEAPU8.set(cborBytes.slice(0, 64), base + 96);

    // Write size_t fields (little-endian, 4 bytes each on WASM32)
    const view = new DataView(HEAPU8.buffer);
    view.setUint32(base + 160, nsBytes.length,   true);
    view.setUint32(base + 164, idBytes.length,   true);
    view.setUint32(base + 168, cborBytes.length, true);
  }

  const circuitPtr = writeBytes(circuitBytes);
  const mdocBytes = b64urlToBytes(mdocInput.mdoc_data_base64);
  const mdocPtr = writeBytes(mdocBytes);
  const pkxPtr = writeStr(mdocInput.public_key.x);
  const pkyPtr = writeStr(mdocInput.public_key.y);
  const transcriptBytes = fromHex(mdocInput.transcript);
  const transcriptPtr = writeBytes(transcriptBytes);
  const timePtr = writeStr(mdocInput.time);

  // Output pointers (allocate two 4-byte slots for ptr + len)
  const outProofPtrSlot = _lf_malloc(4);
  const outProofLenSlot = _lf_malloc(4);
  const view = new DataView(HEAPU8.buffer);
  view.setUint32(outProofPtrSlot, 0, true);
  view.setUint32(outProofLenSlot, 0, true);

  try {
    const ret = _lf_prove_direct(
      circuitPtr, circuitBytes.length,
      mdocPtr, mdocBytes.length,
      pkxPtr, pkyPtr,
      transcriptPtr, transcriptBytes.length,
      attrsPtr, n,
      timePtr,
      outProofPtrSlot, outProofLenSlot,
      mdocInput.zkspec,
    );

    if (ret !== 0) throw new Error(`lf_prove_direct returned ${ret}`);

    // Re-read Module.HEAPU8 — the heap may have been resized during the call,
    // which detaches the ArrayBuffer that 'view' and 'HEAPU8' captured earlier.
    const heap = Module.HEAPU8;
    const postView = new DataView(heap.buffer);
    const proofPtr = postView.getUint32(outProofPtrSlot, true);
    const proofLen = postView.getUint32(outProofLenSlot, true);
    const proofBytes = heap.slice(proofPtr, proofPtr + proofLen);
    _lf_free(proofPtr);

    // Build proof JSON (same format as cli.cc cmd_prove output)
    const proofB64 = bytesToB64url(proofBytes);
    const attrsJson = mdocInput.attributes.map(a =>
      `{"namespace":"${a.namespace}","id":"${a.id}","cbor_value":"${a.cbor_value}"}`
    ).join(',');

    const proofJson = JSON.stringify({
      proof_data_base64: proofB64,
      public_key: mdocInput.public_key,
      transcript: mdocInput.transcript,
      time: mdocInput.time,
      doc_type: mdocInput.doc_type,
      zkspec: mdocInput.zkspec,
      attributes: mdocInput.attributes,
      mdoc_data_base64: mdocInput.mdoc_data_base64,
    });

    return proofJson;
  } finally {
    _lf_free(circuitPtr);
    _lf_free(mdocPtr);
    _lf_free(pkxPtr);
    _lf_free(pkyPtr);
    _lf_free(transcriptPtr);
    _lf_free(timePtr);
    _lf_free(attrsPtr);
    _lf_free(outProofPtrSlot);
    _lf_free(outProofLenSlot);
  }
}

// ─── Export ──────────────────────────────────────────────────────────────────
global.MdocLib = {
  parseIssuedMdoc,
  buildPresentation,
  sessionTranscriptBytes,
  extractIssuerPublicKey,
  buildLongfellowInput,
  wasmGenerateProof,
  // encoding primitives (for tests)
  encode, decode, tag24, encodeBstr, encodeStr,
  b64urlToBytes, bytesToB64url, fromHex, toHex,
};

})(typeof window !== 'undefined' ? window : globalThis);

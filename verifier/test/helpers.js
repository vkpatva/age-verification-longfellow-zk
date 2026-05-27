'use strict';

/**
 * Pure-function helpers extracted from verifier/server.js for unit testing.
 * These are duplicated here so tests do not depend on the running server for
 * pure-logic assertions.  Keep in sync with server.js.
 */

/**
 * Convert a raw 64-byte P-256 ECDSA signature (r||s) to DER-encoded form.
 * @param {Buffer} raw
 * @returns {Buffer}
 */
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

/**
 * Encode a CBOR attribute value the same way buildLongfellowInput does.
 * Only handles boolean and short (<256 byte) string values.
 * @param {boolean|string} v
 * @param {string} name  - used in error messages
 * @returns {string}  hex-encoded CBOR bytes (no 0x prefix)
 */
function encodeCborValue(v, name = 'value') {
  if (v === true) return 'f5';
  if (v === false) return 'f4';
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    if (b.length < 24)
      return (0x60 | b.length).toString(16).padStart(2, '0') + b.toString('hex');
    if (b.length < 256)
      return '78' + b.length.toString(16).padStart(2, '0') + b.toString('hex');
    throw new Error(`${name} too long`);
  }
  throw new Error(`unsupported type for ${name}: ${typeof v}`);
}

module.exports = { rawEcdsaToDer, encodeCborValue };

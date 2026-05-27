# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a three-component demo system for age verification using MDOC credentials, OID4VCI/OID4VP protocols, and Longfellow ZK proofs. The three components run independently and communicate over localhost.

| Component | Port | Tech | Entry point |
|-----------|------|------|-------------|
| Issuer    | 3001 | Node.js/Express | `issuer/index.js` |
| Holder    | 3002 | Static HTML/JS (no framework, no build) | `holder/index.html` |
| Verifier  | 3003 | Node.js/Express + CDN React (htm, no bundler) | `verifier/server.js`, `verifier/public/index.html` |

## Running the components

**Issuer** (port 3001):
```bash
cd issuer && npm install && npm start
# Dev mode with auto-reload:
cd issuer && npm run dev
```

**Holder** (port 3002, static files):
```bash
cd holder && npx serve . -p 3002
# or any static file server
```

**Verifier** (port 3003):
```bash
cd verifier && npm install && npm start
```

The verifier fetches the issuer's public key from `http://localhost:3001/issuer-public-key` on startup. Start the issuer first, or set `ISSUER_PUBLIC_KEY_JWK` env var.

## Environment variables

**Issuer** (`issuer/.env`):
- `PORT` — default 3001
- `ISSUER_URL` — default `http://localhost:3001`
- `ISSUER_PRIVATE_KEY_HEX` — P-256 private key as hex; auto-generated and logged to console if not set

**Verifier** (`verifier/.env`):
- `PORT` — default 3003
- `ISSUER_URL` — default `http://localhost:3001`
- `ISSUER_PUBLIC_KEY_JWK` — optional; fetched from issuer on startup if not set

## Protocol flow

```
Issuer (3001) → credential_offer URI → Holder (3002) → OID4VP request URI → Verifier (3003)
```

1. **Issuance (OID4VCI)**: Visit `http://localhost:3001`, enter an age, get a `openid-credential-offer://` URI. Paste it into the Holder wallet.
2. **Holder receives credential**: Holder fetches `/.well-known/openid-credential-issuer`, exchanges pre-authorized code for token, retrieves base64url-encoded CBOR MDOC, stores in `localStorage` under key `mdoc_wallet_credentials`.
3. **Verification (OID4VP)**: Visit `http://localhost:3003`, select age fields, get a `openid4vp://` URI with a `presentation_definition`. Paste it into the Holder.
4. **Holder generates proof**: Holder parses the `openid4vp://` URI, lets user approve, calls Zenroom WASM (or falls back to a clearly-labeled stub), and POSTs the `vp_token` to the verifier's `/response` endpoint.
5. **Verifier checks**: If `vp_token.simulated === true`, marks session `verified_simulated`. Otherwise looks for `circuits/nX.circuit` (X = number of disclosed fields) and calls the native `longfellow-cli` verifier binary.

## ZK proof / Longfellow CLI status

The Longfellow ZK prover runs server-side via a native C++ CLI binary (`verifier/longfellow-cli/build/longfellow-cli`). The holder POSTs a presentation to the verifier's `/generate-proof` endpoint, which builds a proper OID4VP `DeviceResponse`, then calls `longfellow-cli prove`. The resulting proof JSON is sent back to the holder and included in the `vp_token` as `proof_json`. The verifier calls `longfellow-cli verify` to check it.

Pre-generated circuit files are stored in `verifier/circuits/n1.circuit`, `n2.circuit`, `n3.circuit`. If a circuit is missing, `longfellow-cli circuit <zkspec_index>` generates it automatically on first use.

**Key fix (2026-05-27)**: The CLI previously output `cbor_value` as hex in proof JSON, but the verifier's `base64url_decode` silently misread short hex strings (e.g. `"f5"` decoded to `0x7F` instead of `0xF5`). Fixed by outputting `cbor_value` as base64url in proof JSON to match the input format.

## Key architecture notes

- **Issuer keys regenerate on every restart** unless `ISSUER_PRIVATE_KEY_HEX` is set. The verifier's cached issuer key becomes stale if the issuer restarts without a fixed key.
- **MDOC field parsing in the holder is a best-effort heuristic** (`parseMdocFields` in `holder/index.html`). The issuer doesn't embed decoded fields in the credential response, so the holder attempts naive JSON extraction from the raw CBOR bytes.
- **All state is in-memory** on the issuer and verifier (pre-auth code map, session map). Restarting either clears all state.
- **Pre-authorized codes are single-use** — the issuer marks them `used: true` after the first `/token` call.
- The verifier polls `/session/:session_id` every 2 seconds from the frontend to detect when a proof arrives.
- After a proof is received the frontend transitions to a dedicated `ResultView` component (no longer inline within the waiting card) to prevent blank-screen render failures on unexpected session states.

## Credential doctype and fields

- `doctype`: `org.iso.18013.5.1.age_verification`
- `namespace`: `org.iso.18013.5.1`
- Fields: `age_above_18`, `age_above_21`, `age_above_25` (booleans), `issuer_country` ("IN"), `issuance_date`, `expiry_date`
- Signed with P-256 / ES256 via `mdoc-lib.js` (custom CBOR/COSE implementation)

## Dependencies of note

- `@auth0/mdl` — MDOC/MSO building and signing (issuer only)
- `@peculiar/webcrypto` + `@peculiar/x509` — WebCrypto polyfill and self-signed cert generation (issuer)
- `jsonwebtoken` — short-lived Bearer tokens on the `/token` → `/credential` path
- `qrcode` — QR code generation on both issuer and verifier
- `node-fetch` — verifier fetches issuer public key at startup
- `longfellow-cli` (native C++) — ZK proof generation and verification; build with `cd verifier/longfellow-cli && bash build.sh`

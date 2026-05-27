# Age Verification — Longfellow ZK / MDOC / OID4VP Demo

A three-component demo system that proves age claims using **ISO 18013-5 MDOC credentials**, **OID4VCI/OID4VP** protocols, and **Longfellow ZK proofs** (Google's zk-SNARK library for MDOC).

The holder proves "I hold a government-issued credential that says I am over 21" without revealing any other information — not the exact age, not other fields, not even that the same credential was used in a previous presentation.

---

## Components

| Component | Port | Stack | Entry point |
|-----------|------|-------|-------------|
| Issuer    | 3001 | Node.js / Express | `issuer/index.js` |
| Holder    | 3002 | Static HTML/JS (no framework, no build) | `holder/index.html` |
| Verifier  | 3003 | Node.js / Express + CDN React | `verifier/server.js`, `verifier/public/index.html` |

The verifier contains a native C++ CLI (`verifier/longfellow-cli/`) that wraps Google's `longfellow-zk` library. It can also be compiled to WebAssembly so the holder runs proof generation entirely in the browser.

---

## Prerequisites

- **Node.js** ≥ 18
- **C++ build tools**: `g++` (C++17), `cmake` ≥ 3.13
- **System libraries**: `libssl-dev`, `libzstd-dev`

```bash
sudo apt-get install build-essential cmake libssl-dev libzstd-dev
```

---

## Setup

### 1. Clone with the longfellow-zk source

`longfellow-zk/` must sit at the repo root. Clone it alongside this repo:

```bash
git clone https://github.com/google/longfellow-zk
```

The build scripts point to `../../longfellow-zk/lib` (relative to `verifier/longfellow-cli/`).

### 2. Build the native CLI (server-side, required)

```bash
cd verifier/longfellow-cli
bash build.sh
```

Produces `verifier/longfellow-cli/build/longfellow-cli`. Build takes ~2 minutes. The verifier uses this for ZK verification on every `/response` call and as a fallback for server-side proof generation.

### 3. Build the WebAssembly module (client-side, recommended)

This step compiles longfellow-zk to WASM so the holder wallet can run proof generation in the browser — no server round-trip, no 30-second wait on the server.

**Install Emscripten:**

```bash
git clone https://github.com/emscripten-core/emsdk ~/emsdk
~/emsdk/emsdk install latest
~/emsdk/emsdk activate latest
source ~/emsdk/emsdk_env.sh
```

**Build:**

```bash
cd verifier/longfellow-cli
bash build-wasm.sh
```

Produces `verifier/longfellow-cli/build-wasm/longfellow.js` and `longfellow.wasm`. Build takes ~3 minutes (downloads and compiles zstd + OpenSSL for WASM on first run). The verifier serves these at `GET /longfellow.js` and `GET /longfellow.wasm`; the holder loads them automatically.

If WASM is not built, the holder falls back to `POST /generate-proof` (server-side, ~30s).

### 4. Install Node dependencies

```bash
cd issuer   && npm install
cd verifier && npm install
cd ..       && npm install   # root — installs Playwright for e2e tests
```

---

## Running

Start all three components, each in its own terminal. Start the **issuer first** — the verifier fetches the issuer's public key on startup.

```bash
# Terminal 1 — Issuer
cd issuer && npm start

# Terminal 2 — Holder (static file server)
cd holder && npx serve . -p 3002

# Terminal 3 — Verifier
cd verifier && npm start
```

---

## Demo Flow

### Step 1 — Issue a credential

1. Open `http://localhost:3001`
2. Enter an age (e.g. 22) and click **Generate Credential Offer**
3. Copy the `openid-credential-offer://` URI

### Step 2 — Add credential to wallet

1. Open `http://localhost:3002` (Holder wallet)
2. Click **Add Credential**, paste the URI, click **Fetch Credential**
3. The wallet runs the OID4VCI flow: fetches issuer metadata → exchanges pre-auth code for token → retrieves the MDOC → stores it in `localStorage`

### Step 3 — Request age proof

1. Open `http://localhost:3003` (Verifier)
2. Select which age fields to verify (e.g. `age_above_21`)
3. Click **Generate Verification Request** — copy the `openid4vp://` URI

### Step 4 — Generate and submit proof

1. Back in the Holder, paste the `openid4vp://` URI and click **Parse Request**
2. The wallet shows which fields are requested and whether your credential satisfies them (red warning if any requested field is `false`)
3. Click **Approve & Generate Proof**
   - If `longfellow.wasm` is available: proof runs entirely in the browser (~30s, no server request)
   - Otherwise: falls back to `POST /generate-proof` on the verifier (~30s server-side)
4. The proof is automatically submitted to the verifier

### Step 5 — View result

The verifier page transitions to the result screen:
- **ZK Proof Verified** (green) — the proof was cryptographically verified
- Disclosed attributes and their values
- Proof source: "client-side WASM" or "server-side"

---

## Architecture

### Credential format (MDOC / ISO 18013-5)

The issued credential contains:

- **IssuerSignedItems** — one per attribute. Each is `{digestID, random(16 bytes), elementIdentifier, elementValue}` encoded as CBOR. The SHA-256 of these bytes goes into the MSO.
- **MSO** (Mobile Security Object) — a COSE_Sign1 structure containing SHA-256 digests of all attributes, the holder's device public key, and validity dates. Signed by the issuer's P-256 key (ES256). The issuer's X.509 cert is embedded as `x5chain`.

Fields issued: `age_above_18`, `age_above_21`, `age_above_25` (booleans), `issuer_country`, `issuance_date`, `expiry_date`.

### ZK proof (what Longfellow proves)

The prover produces a zk-SNARK (~360 KB) that demonstrates — **without revealing the credential bytes**:

1. **Issuer signature valid** — the MSO's COSE_Sign1 is a valid ES256 signature by the known issuer public key
2. **Attribute integrity** — `SHA256(IssuerSignedItem bytes)` matches the digest in the MSO for each disclosed field
3. **Device binding** — the `deviceSignature` is a valid ES256 signature by the device key embedded in the MSO, over the session transcript (binds the proof to this specific verifier request — replay protection)
4. **Attribute value** — `elementValue` equals the claimed CBOR value (e.g. `age_above_21 = 0xf5 = true`)

The session transcript encodes `[mdocGeneratedNonce, clientId, responseUri, verifierNonce]` — a fresh nonce per presentation prevents replay.

### Policy enforcement

The verifier and holder both enforce that all requested fields must be `true` in the credential:

- **Holder (render time)** — shows a red badge and disables the Approve button if any requested field is `false`
- **Verifier `/generate-proof`** — returns HTTP 400 immediately (before the expensive 30s proof generation) if any field is `false`
- **Verifier `/response`** — rejects the proof if `age claim not met`

The verifier's `openid4vp://` URI includes `filter: { type: "boolean", const: true }` per the [DIF Presentation Exchange v2](https://identity.foundation/presentation-exchange/) standard, so compliant wallets can pre-screen credentials before even attempting to generate a proof.

### Proof generation — two paths

| Path | When | Time | How |
|------|------|------|-----|
| Client-side WASM | `longfellow.wasm` built and served | ~30s in browser | `holder/mdoc-lib-browser.js` + `LongfellowModule` |
| Server-side CLI | WASM unavailable | ~30s on server | `POST /generate-proof` → `longfellow-cli prove` |

Verification always runs server-side via `longfellow-cli verify`.

### Circuits

ZK circuits are generated per number of disclosed attributes. They are **not committed** (gitignored — ~95 MB each) and are generated automatically on first use:

| File | Attributes | Generation time |
|------|-----------|-----------------|
| `verifier/circuits/n1.circuit` | 1 field  | ~5 min |
| `verifier/circuits/n2.circuit` | 2 fields | ~5 min |
| `verifier/circuits/n3.circuit` | 3 fields | ~5 min |

On first use the verifier calls `longfellow-cli circuit <n>` to generate the circuit and caches it to disk. Subsequent runs load from disk (~2s). Delete a `.circuit` file to force regeneration.

### Demo limitations

- **Expiry** — `validityInfo.validUntil` is present in the MSO but not enforced at the application layer
- **Certificate trust** — the issuer cert is self-signed; no trusted root CA check
- **Revocation** — no CRL/OCSP

---

## Testing

### End-to-end (Playwright)

The e2e test drives a real Chromium browser through the full flow: issues a credential, parses a VP request, generates a ZK proof in-browser via WASM, and confirms the verifier marks the session `verified_zk`.

Requires all three services running (issuer, holder, verifier) and the WASM module built.

```bash
npm run test:e2e          # headless
npm run test:e2e:debug    # headed + verbose output
```

### Verifier unit / integration tests

```bash
cd verifier && npm test
```

---

## Key files

| File | Purpose |
|------|---------|
| `issuer/index.js` | OID4VCI issuer: generates MDOCs, signs with ES256, serves credential offers |
| `holder/index.html` | Wallet: OID4VCI fetch, device key generation, OID4VP presentation, WASM proof generation |
| `holder/mdoc-lib-browser.js` | Browser port of mdoc-lib.js: CBOR/COSE parsing, WASM proof marshalling (WebCrypto, no build step) |
| `verifier/server.js` | OID4VP verifier: session management, proof orchestration, ZK verification, WASM serving |
| `verifier/longfellow.js` | Node wrapper around `longfellow-cli` (circuit generation, prove, verify) |
| `verifier/longfellow-cli/cli.cc` | C++ CLI that calls the Longfellow ZK library |
| `verifier/longfellow-cli/build.sh` | Builds the native CLI binary |
| `verifier/longfellow-cli/build-wasm.sh` | Builds the WebAssembly module (requires Emscripten) |
| `mdoc-lib.js` | CBOR/COSE MDOC encoder-decoder (Node.js, used by the verifier) |
| `verifier/test/wasm-debug.spec.mjs` | Playwright e2e test: full WASM proof flow in Chromium |
| `playwright.config.js` | Playwright configuration (testDir, timeout, browser) |

---

## Environment variables

**Issuer** (`issuer/.env`):
```
PORT=3001
ISSUER_URL=http://localhost:3001
ISSUER_PRIVATE_KEY_HEX=<hex>   # optional; auto-generated and printed on startup if not set
```

**Verifier** (`verifier/.env`):
```
PORT=3003
ISSUER_URL=http://localhost:3001
ISSUER_PUBLIC_KEY_JWK=<json>   # optional; fetched from issuer on startup if not set
```

> **Note**: Issuer keys regenerate on every restart unless `ISSUER_PRIVATE_KEY_HEX` is set. If the issuer restarts with a new key, any previously issued credentials will fail ZK verification. Set a fixed key for persistent development.

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

The verifier also contains a native C++ CLI (`verifier/longfellow-cli/`) that wraps Google's `longfellow-zk` library for ZK proof generation and verification.

---

## Prerequisites

- **Node.js** ≥ 18
- **C++ build tools**: `gcc`/`g++` (C++17), `cmake` ≥ 3.13
- **System libraries**: `libssl-dev`, `libzstd-dev`

```bash
sudo apt-get install build-essential cmake libssl-dev libzstd-dev
```

---

## Setup

### 1. Clone with the longfellow-zk submodule

`longfellow-zk/` is a Git repository of [google/longfellow-zk](https://github.com/google/longfellow-zk) checked out alongside this repo. If you cloned without it:

```bash
git clone https://github.com/google/longfellow-zk
```

The directory must sit at `longfellow-zk/` relative to this repo root (the `CMakeLists.txt` points to `../../longfellow-zk/lib`).

### 2. Build the longfellow-cli binary

```bash
cd verifier/longfellow-cli
bash build.sh
```

This compiles `cli.cc` against the `longfellow-zk` library sources and produces `verifier/longfellow-cli/build/longfellow-cli`. Build takes ~2 minutes.

### 3. Install Node dependencies

```bash
cd issuer  && npm install
cd verifier && npm install
```

---

## Running

Start all three components (each in its own terminal):

```bash
# Terminal 1 — Issuer
cd issuer && npm start

# Terminal 2 — Holder (static file server)
cd holder && npx serve . -p 3002

# Terminal 3 — Verifier
cd verifier && npm start
```

Start the **issuer first** — the verifier fetches the issuer's public key on startup.

---

## Demo Flow

### Step 1 — Issue a credential

1. Open `http://localhost:3001`
2. Enter an age (e.g. 22) and click **Generate Credential Offer**
3. Copy the `openid-credential-offer://` URI

### Step 2 — Add credential to wallet

1. Open `http://localhost:3002` (the Holder wallet)
2. Click **Add Credential**, paste the URI, click **Fetch Credential**
3. The wallet runs the OID4VCI flow: fetches issuer metadata → exchanges pre-auth code for token → retrieves the MDOC → stores it in `localStorage`

### Step 3 — Request age proof

1. Open `http://localhost:3003` (the Verifier)
2. Select which age fields to verify (e.g. just `age_above_21`)
3. Click **Generate Verification Request** — copy the `openid4vp://` URI

### Step 4 — Generate and submit proof

1. Back in the Holder, paste the `openid4vp://` URI and click **Parse Request**
2. Review the disclosed fields, click **Approve & Generate Proof**
3. The holder POSTs to the verifier's `/generate-proof` endpoint, which runs `longfellow-cli prove` (~30s), returns the proof JSON
4. The holder submits the proof to the verifier's `/response` endpoint

### Step 5 — View result

The verifier page transitions to the result screen showing:
- **ZK Proof Verified** (green) — `longfellow-cli verify` accepted the proof
- Disclosed attributes and their values
- Device binding status

---

## Architecture

### Credential format (MDOC / ISO 18013-5)

The issued credential contains:

- **IssuerSignedItems** — one per attribute. Each is `{digestID, random(16 bytes), elementIdentifier, elementValue}` encoded as CBOR. The SHA-256 of these bytes goes into the MSO.
- **MSO** (Mobile Security Object) — a COSE_Sign1 structure containing SHA-256 digests of all attributes, the holder's device public key, and validity dates. Signed by the issuer's P-256 key (ES256). The issuer's X.509 cert is embedded as `x5chain`.

Fields issued: `age_above_18`, `age_above_21`, `age_above_25` (booleans), `issuer_country`, `issuance_date`, `expiry_date`.

### ZK proof (what Longfellow proves)

`longfellow-cli prove` takes a DeviceResponse (presentation MDOC) and produces a zk-SNARK proof (~360 KB) that demonstrates — **without revealing the credential bytes**:

1. **Issuer signature valid** — the MSO's COSE_Sign1 is a valid ES256 signature by the known issuer public key
2. **Attribute integrity** — `SHA256(IssuerSignedItem bytes)` matches the digest in the MSO for each disclosed field
3. **Device binding** — the `deviceSignature` in `deviceSigned` is a valid ES256 signature by the device key embedded in the MSO, over the session transcript (binding the proof to this specific verifier request — replay protection)
4. **Attribute value** — `elementValue` equals the claimed CBOR value (e.g. `age_above_21 = 0xf5 = true`)

The session transcript encodes `[mdocGeneratedNonce, clientId, responseUri, verifierNonce]` — a fresh nonce per presentation prevents replay.

### Circuits

ZK circuits are pre-generated per number of disclosed attributes:

| File | Attributes | Generation time |
|------|-----------|-----------------|
| `verifier/circuits/n1.circuit` | 1 field  | ~5 min |
| `verifier/circuits/n2.circuit` | 2 fields | ~5 min |
| `verifier/circuits/n3.circuit` | 3 fields | ~5 min |

Circuits are generated automatically on first use if missing. Proof generation takes ~30s; verification ~400ms.

### What is NOT verified (demo limitations)

- **Expiry** — `validityInfo.validUntil` is present in the MSO but not enforced at the application layer
- **Certificate trust** — the issuer cert is self-signed; no trusted root CA check
- **Revocation** — no CRL/OCSP

---

## What to commit

```
✅ Commit                          ❌ Do not commit
─────────────────────────────────  ──────────────────────────────────
issuer/                            node_modules/
holder/                            verifier/longfellow-cli/build/   ← rebuilt by build.sh
verifier/server.js                 .env files                       ← contain secrets
verifier/longfellow.js             /tmp/longfellow-debug/
verifier/public/index.html
verifier/longfellow-cli/cli.cc     verifier/circuits/*.circuit      ← optional, see below
verifier/longfellow-cli/CMakeLists.txt
verifier/longfellow-cli/build.sh
verifier/package.json
mdoc-lib.js
CLAUDE.md
README.md
.gitignore
```

**Circuits** (`verifier/circuits/n*.circuit`): These are ~95 MB when loaded into memory but the on-disk files are smaller. They can be regenerated with `longfellow-cli circuit <index>`. Committing them saves the ~5-min generation step for each new clone. They are currently excluded from `.gitignore` (commented out) — uncomment the line to exclude them.

**`longfellow-zk/`**: This is an external Git repository (google/longfellow-zk). Reference it as a **git submodule** rather than committing its sources directly:

```bash
# If you haven't already:
git submodule add https://github.com/google/longfellow-zk longfellow-zk
git commit -m "Add longfellow-zk as submodule"
```

Then cloners run `git clone --recurse-submodules` or `git submodule update --init`.

---

## Key files

| File | Purpose |
|------|---------|
| `issuer/index.js` | OID4VCI issuer: generates MDOCs, signs with ES256, serves credential offers |
| `holder/index.html` | Wallet: OID4VCI fetch, device key generation, OID4VP presentation, proof submission |
| `verifier/server.js` | OID4VP verifier: session management, proof orchestration, ZK verification |
| `verifier/longfellow.js` | Node wrapper around `longfellow-cli` (circuit generation, prove, verify) |
| `verifier/longfellow-cli/cli.cc` | C++ CLI that calls the Longfellow ZK library |
| `verifier/longfellow-cli/CMakeLists.txt` | Build config; links against `../../longfellow-zk/lib` |
| `verifier/longfellow-cli/build.sh` | One-command build script |
| `mdoc-lib.js` | Custom CBOR/COSE MDOC encoder-decoder used by the verifier to build DeviceResponses |

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

> **Note**: Issuer keys regenerate on every restart unless `ISSUER_PRIVATE_KEY_HEX` is set. If the issuer restarts with a new key, any previously issued credentials will fail ZK verification (the issuer pubkey embedded in the circuit witness won't match). Set a fixed key for persistent development.

// Longfellow ZK native CLI runner.
//
// Uses the native google/longfellow-zk C++ binary (longfellow-cli) instead of
// the dyne WASM wrapper (which has a base64 decode bug making verification fail).
//
// Circuit files are JSON: { circuit_data_base64, _circuit_size, _zkspec }
// Proof files are JSON:   { proof_data_base64, public_key, transcript, ... }

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const CLI_PATH = path.join(__dirname, 'longfellow-cli', 'build', 'longfellow-cli');
const CIRCUITS_DIR = path.join(__dirname, 'circuits');

function withSandbox(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'longfellow-'));
  try {
    return fn(dir);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  }
}

function runCli(args, opts = {}) {
  if (!fs.existsSync(CLI_PATH)) {
    throw new Error(`longfellow-cli not found at ${CLI_PATH}. Run: cd verifier/longfellow-cli && bash build.sh`);
  }
  const result = spawnSync(CLI_PATH, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: opts.timeout || 120000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return result;
}

// Pre-generate a circuit for N disclosed attributes and cache it on disk.
// zkspecIndex mapping: n=1 → index 0, n=2 → index 1, n=3 → index 2
function ensureCircuit(n) {
  const cachePath = path.join(CIRCUITS_DIR, `n${n}.circuit`);
  if (fs.existsSync(cachePath)) return cachePath;
  if (!fs.existsSync(CIRCUITS_DIR)) fs.mkdirSync(CIRCUITS_DIR, { recursive: true });

  const zkspecIndex = n - 1;
  const outPath = path.join(os.tmpdir(), `lf_circuit_${n}_${Date.now()}.json`);

  console.log(`[ensureCircuit] Generating circuit n${n} (zkspec ${zkspecIndex})…`);
  const res = runCli(['circuit', String(zkspecIndex), outPath], { timeout: 300000 });

  const stderr = (res.stderr || Buffer.alloc(0)).toString();
  const stdout = (res.stdout || Buffer.alloc(0)).toString();
  if (res.status !== 0 || res.error) {
    throw new Error(`longfellow-cli circuit failed (status ${res.status}): ${stderr.substring(0, 2000)}`);
  }
  if (!fs.existsSync(outPath)) {
    throw new Error(`longfellow-cli circuit exited 0 but output file missing. stderr: ${stderr.substring(0, 500)}`);
  }

  fs.copyFileSync(outPath, cachePath);
  try { fs.unlinkSync(outPath); } catch (_) {}
  console.log(`[ensureCircuit] Generated n${n}.circuit (${fs.statSync(cachePath).size} bytes)`);
  return cachePath;
}

// Generate a ZK proof for a given MDOC credential.
//
// mdocInput fields:
//   attributes: [{ namespace, id, cbor_value }]  — cbor_value as hex e.g. "f5" (no 0x prefix)
//   doc_type: string
//   mdoc_data_base64: base64-encoded MDOC bytes
//   public_key: { x: "0x...", y: "0x..." }  — issuer P-256 key as 0x-prefixed hex
//   time: ISO-8601 string
//   transcript: hex string (no 0x prefix)
//   zkspec: integer index (0-based)
//
// Returns the proof JSON string.
function generateProof(mdocInput) {
  const n = Array.isArray(mdocInput.attributes) ? mdocInput.attributes.length : 1;
  const circuitPath = path.join(CIRCUITS_DIR, `n${n}.circuit`);
  if (!fs.existsSync(circuitPath)) {
    throw new Error(`Circuit n${n}.circuit not found. Run ensureCircuit(${n}) first.`);
  }

  // DEBUG: dump the input for offline inspection
  try {
    const dbgDir = '/tmp/longfellow-debug';
    if (!fs.existsSync(dbgDir)) fs.mkdirSync(dbgDir, { recursive: true });
    fs.writeFileSync(path.join(dbgDir, 'mdoc_input.json'), JSON.stringify(mdocInput, null, 2));
    const rawB64 = mdocInput.mdoc_data_base64 || '';
    const rawBytes = Buffer.from(rawB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    fs.writeFileSync(path.join(dbgDir, 'mdoc_raw.cbor'), rawBytes);
    console.log(`[generateProof] mdoc_data_base64 len=${rawB64.length} chars, decoded ${rawBytes.length} bytes`);
    console.log(`[generateProof] attributes:`, JSON.stringify(mdocInput.attributes));
  } catch (e) { console.warn('[generateProof] debug dump failed:', e.message); }

  return withSandbox((sandboxDir) => {
    const circuitFile = path.join(sandboxDir, 'circuit.json');
    const mdocFile = path.join(sandboxDir, 'mdoc.json');
    const proofFile = path.join(sandboxDir, 'proof.json');

    fs.copyFileSync(circuitPath, circuitFile);
    fs.writeFileSync(mdocFile, JSON.stringify(mdocInput));

    console.log(`[generateProof] Running longfellow-cli prove…`);
    const res = runCli(['prove', circuitFile, mdocFile, proofFile], { timeout: 300000 });

    const stderr = (res.stderr || Buffer.alloc(0)).toString();
    if (res.status !== 0 || res.error) {
      throw new Error(`longfellow-cli prove failed (status ${res.status}): ${stderr.substring(0, 4000)}`);
    }

    if (!fs.existsSync(proofFile) || fs.statSync(proofFile).size === 0) {
      throw new Error(`longfellow-cli prove exited 0 but proof.json is empty. stderr: ${stderr.substring(0, 300)}`);
    }

    const proofJson = fs.readFileSync(proofFile, 'utf8');
    console.log(`[generateProof] proof generated (${proofJson.length} chars)`);
    if (stderr) console.log(`[generateProof] stderr: ${stderr.substring(0, 300)}`);

    // Save debug copy
    try {
      const dbgDir = '/tmp/longfellow-debug';
      if (!fs.existsSync(dbgDir)) fs.mkdirSync(dbgDir, { recursive: true });
      fs.writeFileSync(path.join(dbgDir, 'last_proof.json'), proofJson);
    } catch (_) {}

    return proofJson;
  });
}

// Verify a ZK proof.
// proofJson: the JSON string returned by generateProof
// Returns true if valid, false if invalid, null if circuit unavailable.
function verifyProof(proofJson, _publicInputs) {
  let zkspecIndex;
  try {
    const p = JSON.parse(proofJson);
    zkspecIndex = p._zkspec ?? p.zkspec;
  } catch {
    return false;
  }
  const n = (zkspecIndex ?? 0) + 1;
  const circuitPath = path.join(CIRCUITS_DIR, `n${n}.circuit`);
  if (!fs.existsSync(circuitPath)) return null;

  return withSandbox((sandboxDir) => {
    const circuitFile = path.join(sandboxDir, 'circuit.json');
    const proofFile = path.join(sandboxDir, 'proof.json');

    fs.copyFileSync(circuitPath, circuitFile);
    fs.writeFileSync(proofFile, proofJson);

    console.log(`[verifyProof] Running longfellow-cli verify…`);
    const res = runCli(['verify', circuitFile, proofFile], { timeout: 120000 });

    const stderr = (res.stderr || Buffer.alloc(0)).toString();
    const stdout = (res.stdout || Buffer.alloc(0)).toString();

    if (res.status === 0) {
      console.log(`[verifyProof] OK`, stderr.substring(0, 200));
      return true;
    } else {
      console.error(`[verifyProof] FAILED (status ${res.status})\nstderr: ${stderr.substring(0, 600)}\nstdout: ${stdout.substring(0, 200)}`);
      return false;
    }
  });
}

// Async wrappers for backward compatibility with server.js which uses await
async function ensureCircuitAsync(n) { return ensureCircuit(n); }
async function generateProofAsync(mdocInput) { return generateProof(mdocInput); }
async function verifyProofAsync(proofJson, publicInputs) { return verifyProof(proofJson, publicInputs); }

module.exports = {
  ensureCircuit: ensureCircuitAsync,
  generateProof: generateProofAsync,
  verifyProof: verifyProofAsync,
  CLI_PATH,
  CIRCUITS_DIR,
};

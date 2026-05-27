// Longfellow ZK CLI — native wrapper around google/longfellow-zk.
// Reads/writes the same JSON format as dyne's wasm_generate_proof /
// wasm_verify_proof, but uses correct base64url decoding (no partial-group
// byte-padding bug).
//
// Commands:
//   circuit  <zkspec_index>  <output_circuit.json>
//   prove    <circuit.json>  <mdoc.json>  <output_proof.json>
//   verify   <circuit.json>  <proof.json>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "circuits/mdoc/mdoc_zk.h"
#include "util/log.h"

// ── minimal base64url ─────────────────────────────────────────────────────────

static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static std::string base64url_encode(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t b = (uint32_t)data[i] << 16;
    if (i + 1 < len) b |= (uint32_t)data[i + 1] << 8;
    if (i + 2 < len) b |= (uint32_t)data[i + 2];
    out += kB64Chars[(b >> 18) & 0x3f];
    out += kB64Chars[(b >> 12) & 0x3f];
    if (i + 1 < len) out += kB64Chars[(b >> 6) & 0x3f];
    if (i + 2 < len) out += kB64Chars[(b >> 0) & 0x3f];
  }
  return out;
}

// Accepts both standard (+/) and URL-safe (-_) base64, with or without padding.
static std::vector<uint8_t> base64url_decode(const std::string& in) {
  static const int8_t lut[256] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,   // +, -, /
      52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,   // 0-9
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // A-O
      15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,   // P-Z, _
      -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // a-o
      41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // p-z
  };
  std::vector<uint8_t> out;
  out.reserve(in.size() * 3 / 4);
  uint32_t buf = 0;
  int bits = 0;
  for (unsigned char c : in) {
    if (c == '=') break;
    int8_t v = (c < 128) ? lut[c] : -1;
    if (v < 0) continue;
    buf = (buf << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back((uint8_t)(buf >> bits));
      buf &= (1u << bits) - 1;
    }
  }
  return out;
}

// ── minimal JSON helpers ──────────────────────────────────────────────────────
// We parse only what we need: string values and array-of-objects.

static std::string read_file(const char* path) {
  std::ifstream f(path);
  if (!f) { fprintf(stderr, "Cannot open %s\n", path); exit(1); }
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static void write_file(const char* path, const std::string& s) {
  std::ofstream f(path);
  if (!f) { fprintf(stderr, "Cannot write %s\n", path); exit(1); }
  f << s;
}

// Extract the value of a top-level JSON string key.
static std::string json_str(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) return "";
  pos = json.find('"', pos + needle.size() + 1);
  if (pos == std::string::npos) return "";
  size_t end = pos + 1;
  while (end < json.size() && json[end] != '"') {
    if (json[end] == '\\') end++;
    end++;
  }
  return json.substr(pos + 1, end - pos - 1);
}

// Extract a JSON integer value.
static int json_int(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) return 0;
  pos = json.find_first_of("-0123456789", pos + needle.size());
  if (pos == std::string::npos) return 0;
  return std::atoi(json.c_str() + pos);
}

// Walk the "attributes" array and fill RequestedAttribute structs.
static std::vector<RequestedAttribute> json_attrs(const std::string& json) {
  std::vector<RequestedAttribute> attrs;
  size_t arr = json.find("\"attributes\"");
  if (arr == std::string::npos) return attrs;
  size_t bracket = json.find('[', arr);
  if (bracket == std::string::npos) return attrs;
  size_t pos = bracket + 1;

  while (pos < json.size()) {
    // Skip whitespace/commas
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\n' ||
                                  json[pos] == '\r' || json[pos] == '\t' ||
                                  json[pos] == ','))
      pos++;
    if (pos >= json.size() || json[pos] == ']') break;
    if (json[pos] != '{') { pos++; continue; }

    // Extract the object {...}
    int depth = 1;
    size_t start = pos++;
    while (pos < json.size() && depth > 0) {
      if (json[pos] == '{') depth++;
      else if (json[pos] == '}') depth--;
      pos++;
    }
    std::string obj = json.substr(start, pos - start);

    RequestedAttribute ra{};
    std::string ns  = json_str(obj, "namespace");
    std::string id  = json_str(obj, "id");
    std::string cbh = json_str(obj, "cbor_value");
    auto cbor_bytes = base64url_decode(cbh);
    // cbor_value may be raw hex (no +/- chars) — try hex decode if needed
    if (cbor_bytes.empty() && !cbh.empty() && cbh.find('-') == std::string::npos &&
        cbh.find('_') == std::string::npos) {
      // treat as hex
      for (size_t i = 0; i + 1 < cbh.size(); i += 2) {
        std::string byte = cbh.substr(i, 2);
        cbor_bytes.push_back((uint8_t)std::stoul(byte, nullptr, 16));
      }
    }

    auto cp = [](uint8_t* dst, size_t cap, const std::string& src) -> size_t {
      size_t n = std::min(src.size(), cap);
      std::memcpy(dst, src.c_str(), n);
      return n;
    };
    ra.namespace_len  = cp(ra.namespace_id, sizeof(ra.namespace_id), ns);
    ra.id_len         = cp(ra.id, sizeof(ra.id), id);
    ra.cbor_value_len = std::min(cbor_bytes.size(), sizeof(ra.cbor_value));
    std::memcpy(ra.cbor_value, cbor_bytes.data(), ra.cbor_value_len);
    attrs.push_back(ra);
  }
  return attrs;
}

// JSON-escape a string (only escapes " and \).
static std::string json_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '"') out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else out += c;
  }
  return out;
}

// ── commands ──────────────────────────────────────────────────────────────────

static int cmd_circuit(int zkspec_index, const char* out_path) {
  if (zkspec_index < 0 || zkspec_index >= (int)kNumZkSpecs) {
    fprintf(stderr, "Invalid zkspec_index %d (max %zu)\n", zkspec_index, kNumZkSpecs - 1);
    return 1;
  }
  const ZkSpecStruct* zk_spec = &kZkSpecs[zkspec_index];
  uint8_t* circuit_bytes = nullptr;
  size_t circuit_len = 0;

  CircuitGenerationErrorCode ret = generate_circuit(zk_spec, &circuit_bytes, &circuit_len);
  if (ret != CIRCUIT_GENERATION_SUCCESS) {
    fprintf(stderr, "Circuit generation failed: %d\n", (int)ret);
    return 1;
  }

  std::string b64 = base64url_encode(circuit_bytes, circuit_len);
  free(circuit_bytes);

  std::string json =
      "{\n"
      "  \"circuit_data_base64\": \"" + b64 + "\",\n"
      "  \"_circuit_size\": " + std::to_string(circuit_len) + ",\n"
      "  \"_zkspec\": {\n"
      "    \"index\": " + std::to_string(zkspec_index) + ",\n"
      "    \"system\": \"longfellow-libzk-v1\",\n"
      "    \"version\": " + std::to_string(zk_spec->version) + ",\n"
      "    \"num_attributes\": " + std::to_string(zk_spec->num_attributes) + "\n"
      "  }\n"
      "}\n";

  write_file(out_path, json);
  fprintf(stdout, "Circuit written to %s (%zu bytes)\n", out_path, circuit_len);
  return 0;
}

static int cmd_prove(const char* circuit_file, const char* mdoc_file,
                     const char* out_file) {
  std::string circuit_json = read_file(circuit_file);
  std::string mdoc_json    = read_file(mdoc_file);

  // Parse circuit
  std::string circuit_b64 = json_str(circuit_json, "circuit_data_base64");
  auto circuit_bytes = base64url_decode(circuit_b64);

  // Parse mdoc inputs
  std::string mdoc_b64 = json_str(mdoc_json, "mdoc_data_base64");
  auto mdoc_bytes = base64url_decode(mdoc_b64);

  std::string pkx      = json_str(mdoc_json, "x");   // nested under public_key
  std::string pky      = json_str(mdoc_json, "y");
  // Also try top-level if not found
  if (pkx.empty()) {
    // Find "public_key" object and extract x/y from it
    size_t pk_pos = mdoc_json.find("\"public_key\"");
    if (pk_pos != std::string::npos) {
      size_t brace = mdoc_json.find('{', pk_pos);
      size_t end   = mdoc_json.find('}', brace);
      if (brace != std::string::npos && end != std::string::npos) {
        std::string pk_obj = mdoc_json.substr(brace, end - brace + 1);
        pkx = json_str(pk_obj, "x");
        pky = json_str(pk_obj, "y");
      }
    }
  }

  std::string transcript_hex = json_str(mdoc_json, "transcript");
  std::vector<uint8_t> transcript;
  for (size_t i = 0; i + 1 < transcript_hex.size(); i += 2) {
    transcript.push_back((uint8_t)std::stoul(transcript_hex.substr(i, 2), nullptr, 16));
  }

  std::string time_str  = json_str(mdoc_json, "time");
  std::string doc_type  = json_str(mdoc_json, "doc_type");
  int zkspec_index      = json_int(mdoc_json, "zkspec");

  auto attrs = json_attrs(mdoc_json);
  if (attrs.empty()) {
    fprintf(stderr, "No attributes found in mdoc.json\n");
    return 1;
  }

  if (zkspec_index < 0 || zkspec_index >= (int)kNumZkSpecs) {
    fprintf(stderr, "Invalid zkspec %d\n", zkspec_index);
    return 1;
  }
  const ZkSpecStruct* zk_spec = &kZkSpecs[zkspec_index];

  uint8_t* proof = nullptr;
  size_t proof_len = 0;

  fprintf(stderr, "Running prover (zkspec=%d, %zu attrs)...\n",
          zkspec_index, attrs.size());

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit_bytes.data(), circuit_bytes.size(),
      mdoc_bytes.data(), mdoc_bytes.size(),
      pkx.c_str(), pky.c_str(),
      transcript.data(), transcript.size(),
      attrs.data(), attrs.size(),
      time_str.c_str(),
      &proof, &proof_len,
      zk_spec);

  if (ret != MDOC_PROVER_SUCCESS) {
    fprintf(stderr, "Prover failed: %d\n", (int)ret);
    return 1;
  }

  std::string proof_b64 = base64url_encode(proof, proof_len);
  free(proof);

  // Build attributes JSON
  std::string attrs_json = "[\n";
  for (size_t i = 0; i < attrs.size(); i++) {
    const auto& a = attrs[i];
    // Re-encode cbor_value as base64url so the verifier's base64url_decode
    // round-trips correctly (hex output was silently misread as base64).
    std::string cbor_b64 = base64url_encode(a.cbor_value, a.cbor_value_len);
    attrs_json += "    {\"namespace\": \"" +
        std::string((char*)a.namespace_id, a.namespace_len) +
        "\", \"id\": \"" +
        std::string((char*)a.id, a.id_len) +
        "\", \"cbor_value\": \"" + cbor_b64 + "\"}";
    if (i + 1 < attrs.size()) attrs_json += ",";
    attrs_json += "\n";
  }
  attrs_json += "  ]";

  std::string out_json =
      "{\n"
      "  \"proof_data_base64\": \"" + proof_b64 + "\",\n"
      "  \"public_key\": {\"x\": \"" + json_escape(pkx) + "\", \"y\": \"" + json_escape(pky) + "\"},\n"
      "  \"transcript\": \"" + transcript_hex + "\",\n"
      "  \"time\": \"" + json_escape(time_str) + "\",\n"
      "  \"doc_type\": \"" + json_escape(doc_type) + "\",\n"
      "  \"zkspec\": " + std::to_string(zkspec_index) + ",\n"
      "  \"attributes\": " + attrs_json + ",\n"
      "  \"mdoc_data_base64\": \"" + json_escape(mdoc_b64) + "\"\n"
      "}\n";

  write_file(out_file, out_json);
  fprintf(stderr, "Proof written to %s (%zu bytes)\n", out_file, proof_len);
  return 0;
}

static int cmd_verify(const char* circuit_file, const char* proof_file) {
  std::string circuit_json = read_file(circuit_file);
  std::string proof_json   = read_file(proof_file);

  auto circuit_bytes = base64url_decode(json_str(circuit_json, "circuit_data_base64"));
  auto proof_bytes   = base64url_decode(json_str(proof_json, "proof_data_base64"));

  std::string pkx, pky;
  size_t pk_pos = proof_json.find("\"public_key\"");
  if (pk_pos != std::string::npos) {
    size_t brace = proof_json.find('{', pk_pos);
    size_t end   = proof_json.find('}', brace);
    if (brace != std::string::npos && end != std::string::npos) {
      std::string pk_obj = proof_json.substr(brace, end - brace + 1);
      pkx = json_str(pk_obj, "x");
      pky = json_str(pk_obj, "y");
    }
  }

  std::string transcript_hex = json_str(proof_json, "transcript");
  std::vector<uint8_t> transcript;
  for (size_t i = 0; i + 1 < transcript_hex.size(); i += 2) {
    transcript.push_back((uint8_t)std::stoul(transcript_hex.substr(i, 2), nullptr, 16));
  }

  std::string time_str = json_str(proof_json, "time");
  std::string doc_type = json_str(proof_json, "doc_type");
  int zkspec_index     = json_int(proof_json, "zkspec");

  auto attrs = json_attrs(proof_json);
  if (attrs.empty()) {
    fprintf(stderr, "No attributes in proof.json\n");
    return 1;
  }
  if (zkspec_index < 0 || zkspec_index >= (int)kNumZkSpecs) {
    fprintf(stderr, "Invalid zkspec %d\n", zkspec_index);
    return 1;
  }
  const ZkSpecStruct* zk_spec = &kZkSpecs[zkspec_index];

  fprintf(stderr, "Verifying proof (%zu attrs, zkspec=%d)...\n",
          attrs.size(), zkspec_index);

  MdocVerifierErrorCode ret = run_mdoc_verifier(
      circuit_bytes.data(), circuit_bytes.size(),
      pkx.c_str(), pky.c_str(),
      transcript.data(), transcript.size(),
      attrs.data(), attrs.size(),
      time_str.c_str(),
      proof_bytes.data(), proof_bytes.size(),
      doc_type.c_str(),
      zk_spec);

  if (ret == MDOC_VERIFIER_SUCCESS) {
    fprintf(stdout, "OK\n");
    return 0;
  }
  fprintf(stdout, "FAIL %d\n", (int)ret);
  return 1;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
  proofs::set_log_level(proofs::INFO);

  if (argc < 2) {
    fprintf(stderr,
            "Usage:\n"
            "  longfellow-cli circuit <zkspec_index> <output.json>\n"
            "  longfellow-cli prove   <circuit.json> <mdoc.json> <proof.json>\n"
            "  longfellow-cli verify  <circuit.json> <proof.json>\n");
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "circuit" && argc == 4) {
    return cmd_circuit(std::atoi(argv[2]), argv[3]);
  } else if (cmd == "prove" && argc == 5) {
    return cmd_prove(argv[2], argv[3], argv[4]);
  } else if (cmd == "verify" && argc == 4) {
    return cmd_verify(argv[2], argv[3]);
  } else {
    fprintf(stderr, "Unknown command or wrong number of args.\n");
    return 1;
  }
}

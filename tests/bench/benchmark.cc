// SPDX-License-Identifier: PostgreSQL
// Core micro-benchmarks (Google Benchmark) for src/gcm.c and its envelope, against bare
// OpenSSL EVP. What is measured is CPU time per call, but the gate is a ratio: the core's seal
// and open over a hand-rolled EVP AES-256-GCM of the same shape, and the deterministic seal over
// a hand-rolled bare deterministic seal (the same HMAC-SHA256 nonce derivation and the same
// AES-GCM). The deterministic seal over the random one is recorded, never gated: it compares two
// different operations and moves with a runner's relative AES-GCM and SHA-256 throughput. The
// ceilings live in tests/bench/baseline.json.
//
//     pg_gcm_bench              run every benchmark and gate the ratios
//     pg_gcm_bench --self-test  check the gate itself, with fixed ratios and no crypto
//
// No server and no PostgreSQL header: the core is linked in, as in the unit suite.
#include <benchmark/benchmark.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

extern "C" {
#include "gcm.h"
#include "nonce.h"
}

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace {

// The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
const std::array<uint8_t, GCM_KEY_LEN_AES256> kKey = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
constexpr uint8_t kVersion = GCM_V_AES256_RANDOM;
constexpr uint8_t kVersionDet = GCM_V_AES256_DET;

// The plaintext sizes; larger than one AES block so the ratio is not all per-call overhead.
const std::vector<int64_t> kSizes = {16, 256, 4096, 65536};

// Repetitions per benchmark. One sample per cell let either side swing about 2x on a busy host,
// which would trip a 1.3-1.5 ceiling on noise alone; the gate reads the median of these.
constexpr int kRepetitions = 5;

const EVP_CIPHER *g_bare = nullptr;
EVP_MAC *g_bare_hmac = nullptr;

[[noreturn]] void Fail(const char *why) {
  std::cerr << "bench: " << why << "\n";
  std::exit(2);
}

// A precondition the measurement cannot proceed without. Named so a benchmark body has no `if`.
// The two overloads keep a string literal out of a std::string: the bare det baseline's checks run
// inside the timed loop, and building a std::string there would bias the det ratio down at small
// sizes. A std::string is still accepted for a message assembled at run time.
void Require(bool ok, const char *why) {
  if (!ok) Fail(why);
}

void Require(bool ok, const std::string &why) {
  if (!ok) Fail(why.c_str());
}

// A raw AES-256-GCM seal through EVP alone — a context, the version byte as associated data, the
// plaintext, the tag — with a nonce the caller supplies. Both bare seals below share it: the
// random one draws its nonce with RAND_bytes, the deterministic one derives it by hand.
void EvpSealWithNonce(const EVP_CIPHER *cipher, uint8_t version, const uint8_t *nonce,
                      const uint8_t *pt, size_t pt_len, uint8_t *ct, uint8_t *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  Require(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
  int n = 0;
  int fin = 0;
  Require(EVP_EncryptInit_ex2(ctx, cipher, kKey.data(), nonce, nullptr) == 1, "init");
  Require(EVP_EncryptUpdate(ctx, nullptr, &n, &version, 1) == 1, "associated data");
  n = 0;
  Require(EVP_EncryptUpdate(ctx, ct, &n, pt, static_cast<int>(pt_len)) == 1, "update");
  Require(EVP_EncryptFinal_ex(ctx, ct + n, &fin) == 1, "final");
  Require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, tag) == 1, "get tag");
  EVP_CIPHER_CTX_free(ctx);
}

// The bare EVP seal for the random suite: a nonce drawn with RAND_bytes, exactly as the core's
// random seal draws one, so the seal ratio charges the core for its own envelope and checks and
// not for a draw only one side pays. This is "bare EVP" for the random seal.
void EvpSeal(const EVP_CIPHER *cipher, const uint8_t *pt, size_t pt_len, uint8_t *ct,
             uint8_t *tag, uint8_t *nonce) {
  Require(RAND_bytes(nonce, GCM_NONCE_LEN) == 1, "RAND_bytes failed");
  EvpSealWithNonce(cipher, kVersion, nonce, pt, pt_len, ct, tag);
}

// The deterministic nonce, re-derived by hand from spec 1.8 so the bare det baseline pays the
// same two HMAC-SHA256 passes as the core:
//   nonce_key = HMAC-SHA256(key, "pg_gcm/v1/det-nonce")
//   nonce     = HMAC-SHA256(nonce_key, be64(len(A)) || A || plaintext)[:12]
// where A is version || aad. This benchmark seals without AAD, so A is the one version byte and
// its length is 1. It computes spec 1.8 with the fewest EVP calls; a cost added to the core is not
// added here, or the gate would shut its eyes to it. The key is the public 00..1f pattern and
// never leaves the process.
void DetNonce(EVP_MAC *hmac, const uint8_t *pt, size_t pt_len, uint8_t *nonce) {
  static const char label[] = GCM_DET_NONCE_LABEL;
  char digest[] = "SHA256";
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
  params[1] = OSSL_PARAM_construct_end();

  uint8_t a_len_be[8];
  const uint64_t a_len = 1; /* len(version || aad), aad empty */
  for (int i = 0; i < 8; i++) a_len_be[i] = static_cast<uint8_t>(a_len >> (56 - 8 * i));

  uint8_t nonce_key[32];
  uint8_t mac[32];
  size_t out_len = 0;
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
  Require(ctx != nullptr, "EVP_MAC_CTX_new failed");
  Require(EVP_MAC_init(ctx, kKey.data(), kKey.size(), params) == 1, "hmac init");
  Require(EVP_MAC_update(ctx, reinterpret_cast<const uint8_t *>(label), sizeof(label) - 1) == 1,
          "hmac label");
  Require(EVP_MAC_final(ctx, nonce_key, &out_len, sizeof(nonce_key)) == 1 &&
              out_len == sizeof(nonce_key),
          "hmac nonce key");
  Require(EVP_MAC_init(ctx, nonce_key, sizeof(nonce_key), nullptr) == 1, "hmac rekey");
  Require(EVP_MAC_update(ctx, a_len_be, sizeof(a_len_be)) == 1, "hmac length");
  Require(EVP_MAC_update(ctx, &kVersionDet, 1) == 1, "hmac version");
  Require(EVP_MAC_update(ctx, pt, pt_len) == 1, "hmac plaintext");
  Require(EVP_MAC_final(ctx, mac, &out_len, sizeof(mac)) == 1 && out_len == sizeof(mac),
          "hmac mac");
  std::memcpy(nonce, mac, GCM_NONCE_LEN);
  EVP_MAC_CTX_free(ctx);
  OPENSSL_cleanse(nonce_key, sizeof(nonce_key));
  OPENSSL_cleanse(mac, sizeof(mac));
}

// The bare deterministic seal: the hand-rolled nonce derivation above, then the same EVP seal with
// the det suite's version byte. The core's det gate is the core's det seal over this.
void EvpSealDet(const EVP_CIPHER *cipher, EVP_MAC *hmac, const uint8_t *pt, size_t pt_len,
                uint8_t *ct, uint8_t *tag, uint8_t *nonce) {
  DetNonce(hmac, pt, pt_len, nonce);
  EvpSealWithNonce(cipher, kVersionDet, nonce, pt, pt_len, ct, tag);
}

// The bare deterministic seal above must be the core's operation, or the det ratio would compare
// two different things and still print a number. Checked once, before the timed runs, by sealing
// one fixed plaintext (the public key, the AES-256 det version, no AAD) both ways — the core's
// gcm_seal and the hand-rolled EvpSealDet plus the envelope header — and comparing every byte: the
// version byte, the derived nonce, the ciphertext and the tag. A drift in either side fails the run.
void RequireBareDetMatchesCore() {
  const std::array<uint8_t, 16> pt = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  constexpr size_t n = pt.size();
  std::array<uint8_t, n + GCM_ENVELOPE_OVERHEAD> core{};
  Require(gcm_seal(kKey.data(), kKey.size(), nullptr, 0, pt.data(), n, 1, core.data(),
                   core.size()) == GCM_OK,
          "gcm_seal(det) failed");

  std::array<uint8_t, n + GCM_ENVELOPE_OVERHEAD> bare{};
  uint8_t *nonce = bare.data() + GCM_VERSION_LEN;
  uint8_t *ct = nonce + GCM_NONCE_LEN;
  uint8_t *tag = ct + n;
  bare[0] = kVersionDet;
  EvpSealDet(g_bare, g_bare_hmac, pt.data(), n, ct, tag, nonce);
  Require(bare == core, "the bare det envelope does not match the core's");
}

void EvpOpen(const EVP_CIPHER *cipher, const uint8_t *ct, size_t ct_len, uint8_t *tag,
             const uint8_t *nonce, uint8_t *out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  Require(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
  int n = 0;
  int fin = 0;
  Require(EVP_DecryptInit_ex2(ctx, cipher, kKey.data(), nonce, nullptr) == 1, "init");
  Require(EVP_DecryptUpdate(ctx, nullptr, &n, &kVersion, 1) == 1, "associated data");
  n = 0;
  Require(EVP_DecryptUpdate(ctx, out, &n, ct, static_cast<int>(ct_len)) == 1, "update");
  Require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN, tag) == 1, "set tag");
  Require(EVP_DecryptFinal_ex(ctx, out + n, &fin) == 1, "final (the tag check)");
  EVP_CIPHER_CTX_free(ctx);
}

// ---- The core, and the baseline it is compared against ----------------------------------------

void BM_GcmSealRandom(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> out(n + GCM_ENVELOPE_OVERHEAD);
  for (auto _ : state) {
    Require(gcm_seal(kKey.data(), kKey.size(), nullptr, 0, pt.data(), pt.size(), 0, out.data(),
                     out.size()) == GCM_OK,
            "gcm_seal(random) failed");
    benchmark::DoNotOptimize(out.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

void BM_GcmSealDet(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> out(n + GCM_ENVELOPE_OVERHEAD);
  for (auto _ : state) {
    Require(gcm_seal(kKey.data(), kKey.size(), nullptr, 0, pt.data(), pt.size(), 1, out.data(),
                     out.size()) == GCM_OK,
            "gcm_seal(det) failed");
    benchmark::DoNotOptimize(out.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

void BM_GcmOpen(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> env(n + GCM_ENVELOPE_OVERHEAD);
  Require(gcm_seal(kKey.data(), kKey.size(), nullptr, 0, pt.data(), pt.size(), 0, env.data(),
                   env.size()) == GCM_OK,
          "the Given envelope could not be sealed");
  std::vector<uint8_t> out(n);
  size_t got = 0;
  for (auto _ : state) {
    Require(gcm_open(kKey.data(), kKey.size(), nullptr, 0, env.data(), env.size(), out.data(),
                     out.size(), &got) == GCM_OK,
            "gcm_open failed");
    benchmark::DoNotOptimize(out.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

void BM_EvpSeal(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> ct(n);
  std::array<uint8_t, GCM_TAG_LEN> tag{};
  std::array<uint8_t, GCM_NONCE_LEN> nonce{};
  for (auto _ : state) {
    EvpSeal(g_bare, pt.data(), pt.size(), ct.data(), tag.data(), nonce.data());
    benchmark::DoNotOptimize(ct.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

void BM_EvpSealDet(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> ct(n);
  std::array<uint8_t, GCM_TAG_LEN> tag{};
  std::array<uint8_t, GCM_NONCE_LEN> nonce{};
  for (auto _ : state) {
    EvpSealDet(g_bare, g_bare_hmac, pt.data(), pt.size(), ct.data(), tag.data(), nonce.data());
    benchmark::DoNotOptimize(ct.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

void BM_EvpOpen(benchmark::State &state) {
  const size_t n = static_cast<size_t>(state.range(0));
  std::vector<uint8_t> pt(n, 0xAA);
  std::vector<uint8_t> ct(n);
  std::array<uint8_t, GCM_TAG_LEN> tag{};
  std::array<uint8_t, GCM_NONCE_LEN> nonce{};
  EvpSeal(g_bare, pt.data(), pt.size(), ct.data(), tag.data(), nonce.data());
  std::vector<uint8_t> out(n);
  for (auto _ : state) {
    EvpOpen(g_bare, ct.data(), ct.size(), tag.data(), nonce.data(), out.data());
    benchmark::DoNotOptimize(out.data());
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(n));
}

// ---- The gate ----------------------------------------------------------------------------------

// One ceiling per ratio, per size. A single ceiling cannot gate large and small sizes alike: the
// core's fixed per-call cost (the envelope header, the key checks) is a larger share of a small
// message than of a large one, so a large input needs its own, tighter ceiling.
struct Ceilings {
  double seal;
  double open;
  double det;
};

// A ratio and the direction it must go: the core (or, for det, the deterministic seal) is the
// numerator, so a regression raises it. Pure, so the self-test pins the direction the gate
// depends on; a zero denominator is infinity (a failure), never a silent pass.
double RatioOf(double numerator, double denominator) {
  return denominator > 0.0 ? numerator / denominator : std::numeric_limits<double>::infinity();
}

// The verdict: each ratio is at or under its ceiling.
bool Passes(double seal, double open, double det, const Ceilings &ceiling) {
  return seal <= ceiling.seal && open <= ceiling.open && det <= ceiling.det;
}

// The registered name with its argument, without the "/repeats:N" the library appends when a
// benchmark is repeated ("gcm_seal_random/16/repeats:5" -> "gcm_seal_random/16"), which is the
// key the gate looks up.
std::string BaseName(const std::string &run_name) {
  const std::string marker = "/repeats:";
  const auto at = run_name.rfind(marker);
  return at == std::string::npos ? run_name : run_name.substr(0, at);
}

// Captures every repetition's CPU time, per benchmark, so the gate can take a median.
class Collector : public benchmark::BenchmarkReporter {
 public:
  bool ReportContext(const Context & /*context*/) override { return true; }
  void ReportRuns(const std::vector<Run> &runs) override {
    // run_name.str() carries the argument and the repetition count; BaseName recovers the name the
    // gate looks up (the bare benchmark_name() has no argument). The library's own aggregate runs
    // carry an aggregate_name and are skipped — the median is taken from the raw runs here.
    for (const Run &run : runs) {
      if (!run.aggregate_name.empty()) continue;
      runs_[BaseName(run.run_name.str())].push_back(run.GetAdjustedCPUTime());
    }
  }
  void Finalize() override {}

  const std::map<std::string, std::vector<double>> &runs() const { return runs_; }

 private:
  std::map<std::string, std::vector<double>> runs_;
};

// The per-name CPU times the gate reads, keyed by the full run name ("gcm_seal_random/16").
using CpuTimes = std::map<std::string, double>;

// The median of a benchmark's repetitions, so one noisy repetition cannot move the gate. Each
// benchmark runs with ->Repetitions(5); a single sample per cell let either side swing 2x.
double Median(std::vector<double> values) {
  Require(!values.empty(), "no runs to take a median of");
  std::sort(values.begin(), values.end());
  return values[values.size() / 2];
}

// The gate's input from a collector: each benchmark's median CPU time.
CpuTimes Medians(const Collector &collector) {
  CpuTimes cpu_ns;
  for (const auto &[name, values] : collector.runs()) cpu_ns.emplace(name, Median(values));
  return cpu_ns;
}

double Lookup(const CpuTimes &cpu_ns, const std::string &name) {
  const auto found = cpu_ns.find(name);
  Require(found != cpu_ns.end(), "no measurement for " + name);
  return found->second;
}

double Ratio(const CpuTimes &cpu_ns, const std::string &numerator,
             const std::string &denominator) {
  return RatioOf(Lookup(cpu_ns, numerator), Lookup(cpu_ns, denominator));
}

std::map<int64_t, Ceilings> LoadCeilings() {
  std::ifstream file(PG_GCM_BENCH_BASELINE);
  Require(file.good(), std::string("cannot open ") + PG_GCM_BENCH_BASELINE);
  const nlohmann::json document = nlohmann::json::parse(file);
  std::map<int64_t, Ceilings> ceilings;
  for (const auto &item : document.at("ceilings").items()) {
    const nlohmann::json &value = item.value();
    ceilings.emplace(std::stoll(item.key()),
                     Ceilings{value.at("seal").get<double>(), value.at("open").get<double>(),
                              value.at("det").get<double>()});
  }
  return ceilings;
}

// The three ratios the gate reads per size, plus the fourth it only records. `det` compares the
// core's deterministic seal with a bare deterministic seal — the same two HMAC-SHA256 passes and
// the same AES-GCM on both sides — so it means the same on any runner. `det_random` compares that
// same deterministic seal with the random one, which is a different operation: its value moves
// with a runner's relative AES-GCM and SHA-256 throughput and is not portable (the O17 probe
// measured about 1.2-9.6 across sizes and runner CPUs), so it is recorded, never gated.
struct SizeRatios {
  double seal;
  double open;
  double det;
  double det_random;
};

std::map<int64_t, SizeRatios> RatiosOf(const CpuTimes &cpu_ns) {
  std::map<int64_t, SizeRatios> ratios;
  for (const int64_t size : kSizes) {
    const std::string at = "/" + std::to_string(size);
    ratios.emplace(size,
                   SizeRatios{
                       Ratio(cpu_ns, "gcm_seal_random" + at, "evp_seal" + at),
                       Ratio(cpu_ns, "gcm_open" + at, "evp_open" + at),
                       Ratio(cpu_ns, "gcm_seal_det" + at, "evp_seal_det" + at),
                       Ratio(cpu_ns, "gcm_seal_det" + at, "gcm_seal_random" + at),
                   });
  }
  return ratios;
}

// The verdict over every size, reading median CPU times. `log` prints the ratios; the self-test
// passes nullptr. Pure over its inputs, so the fixed measurements below gate the name pairs too.
bool GateVerdict(const CpuTimes &cpu_ns, const std::map<int64_t, Ceilings> &ceilings,
                 std::ostream *log) {
  bool passed = true;
  for (const auto &[size, ratio] : RatiosOf(cpu_ns)) {
    const auto found = ceilings.find(size);
    Require(found != ceilings.end(), "no ceiling for " + std::to_string(size) + " bytes");
    const Ceilings &ceiling = found->second;
    passed = Passes(ratio.seal, ratio.open, ratio.det, ceiling) && passed;
    if (log != nullptr) {
      *log << size << " bytes: seal " << ratio.seal << " (<= " << ceiling.seal << "), open "
           << ratio.open << " (<= " << ceiling.open << "), det " << ratio.det << " (<= "
           << ceiling.det << "), det/random " << ratio.det_random << " (recorded)\n";
    }
  }
  return passed;
}

// The ratios and the raw medians of the run, as JSON: what docs/perf.md records and the CI
// artifact carries. Pure over its inputs, so the self-test can assert on the document.
nlohmann::json JsonReport(const CpuTimes &cpu_ns, bool passed) {
  nlohmann::json sizes = nlohmann::json::object();
  for (const auto &[size, ratio] : RatiosOf(cpu_ns)) {
    const std::string at = "/" + std::to_string(size);
    sizes[std::to_string(size)] = {
        {"seal", ratio.seal},
        {"open", ratio.open},
        {"det", ratio.det},
        {"det_random", ratio.det_random},
        // The times are in microseconds: every benchmark is registered ->Unit(kMicrosecond), which
        // is what Run::GetAdjustedCPUTime returns them in.
        {"median_cpu_us",
         {
             {"gcm_seal_random", Lookup(cpu_ns, "gcm_seal_random" + at)},
             {"gcm_seal_det", Lookup(cpu_ns, "gcm_seal_det" + at)},
             {"gcm_open", Lookup(cpu_ns, "gcm_open" + at)},
             {"evp_seal", Lookup(cpu_ns, "evp_seal" + at)},
             {"evp_seal_det", Lookup(cpu_ns, "evp_seal_det" + at)},
             {"evp_open", Lookup(cpu_ns, "evp_open" + at)},
         }},
    };
  }
  nlohmann::json document;
  document["gate"] = passed;
  document["openssl"] = OpenSSL_version(OPENSSL_VERSION);
  document["sizes"] = sizes;
  return document;
}

// Written to PG_GCM_BENCH_JSON when that names a path, whether the gate passed or not, so a
// failing run's numbers survive too.
void WriteJson(const CpuTimes &cpu_ns, bool passed, const std::string &path) {
  std::ofstream out(path);
  Require(out.good(), "cannot open " + path);
  out << JsonReport(cpu_ns, passed).dump(2) << "\n";
  out.flush();
  Require(out.good(), "cannot write " + path);
}

// A fixed gate input for the self-test: every size carries the same three ratios, so a wrong
// benchmark name pair (a lookup that should have found the other one) fails instead of passing.
// The three bare baselines are distinct (1, 2, 3), so swapping one ratio's denominator for another
// changes the value and the verdict — a map of all-1.0 baselines would not.
CpuTimes FakeRatios(double seal, double open, double det) {
  CpuTimes cpu_ns;
  for (const int64_t size : kSizes) {
    const std::string at = "/" + std::to_string(size);
    cpu_ns["evp_seal" + at] = 1.0;
    cpu_ns["gcm_seal_random" + at] = seal;
    cpu_ns["evp_open" + at] = 2.0;
    cpu_ns["gcm_open" + at] = open * 2.0;
    // The gated det ratio is the core det over the bare det, so `det` here is that ratio.
    cpu_ns["evp_seal_det" + at] = 3.0;
    cpu_ns["gcm_seal_det" + at] = det * 3.0;
  }
  return cpu_ns;
}

std::map<int64_t, Ceilings> FixedCeilings() {
  std::map<int64_t, Ceilings> ceilings;
  for (const int64_t size : kSizes) ceilings.emplace(size, Ceilings{1.5, 1.5, 2.0});
  return ceilings;
}

int SelfTest() {
  const Ceilings ceiling{3.0, 3.0, 5.0};
  // name, the verdict Passes gives, and the verdict it must give.
  const std::vector<std::tuple<std::string, bool, bool>> verdicts = {
      {"ratios below the ceilings", Passes(0.5, 0.5, 0.5, ceiling), true},
      {"a ratio at its ceiling", Passes(3.0, 3.0, 5.0, ceiling), true},
      {"the seal ratio above its ceiling", Passes(3.1, 0.5, 0.5, ceiling), false},
      {"the open ratio above its ceiling", Passes(0.5, 3.1, 0.5, ceiling), false},
      {"the det ratio above its ceiling", Passes(0.5, 0.5, 5.1, ceiling), false},
      {"every ratio above its ceiling", Passes(9.0, 9.0, 9.0, ceiling), false},
      // The gate over a fixed measurement map: GateVerdict must read the right benchmark names,
      // so each of the three pairs gets a case that fails on its own ratio.
      {"the gate passes fixed measurements",
       GateVerdict(FakeRatios(1.0, 1.0, 1.0), FixedCeilings(), nullptr), true},
      {"the gate fails on a fixed seal regression",
       GateVerdict(FakeRatios(2.0, 1.0, 1.0), FixedCeilings(), nullptr), false},
      {"the gate fails on a fixed open regression",
       GateVerdict(FakeRatios(1.0, 2.0, 1.0), FixedCeilings(), nullptr), false},
      {"the gate fails on a fixed det regression",
       GateVerdict(FakeRatios(1.0, 1.0, 3.0), FixedCeilings(), nullptr), false},
      // A runner whose AES-GCM is far faster than its SHA-256 shows a high det-over-random ratio
      // (the reason the gate was redefined): here 5.0. The gate reads only the det-over-bare-det
      // ratio, so the cell passes, and a gate that had gone on reading det-over-random would fail.
      {"a high det-over-random does not fail the gate",
       GateVerdict(FakeRatios(0.2, 1.0, 1.0), FixedCeilings(), nullptr), true},
      // The JSON report carries the verdict, so the artifact of a failing run says so too.
      {"the JSON report carries a failed verdict",
       JsonReport(FakeRatios(1.0, 1.0, 1.0), false)["gate"].get<bool>(), false},
  };
  // name, the ratio RatioOf gives, and the ratio it must give. Swapping the gate's numerator and
  // denominator would turn 2.0 into 0.5 and let a regression pass, so the direction is pinned.
  const std::vector<std::tuple<std::string, double, double>> ratios = {
      {"the two sides equal", RatioOf(1.0, 1.0), 1.0},
      {"the core twice the baseline", RatioOf(2.0, 1.0), 2.0},
      {"the core half the baseline", RatioOf(1.0, 2.0), 0.5},
      {"a zero denominator is infinite", RatioOf(1.0, 0.0),
       std::numeric_limits<double>::infinity()},
      // The recorded det-over-random is the det seal over the random one, not its reciprocal: with
      // the distinct baselines this is 2*3/1 = 6.0, and a swapped operand pair would read 1/6.
      {"the recorded det-over-random ratio",
       RatiosOf(FakeRatios(1.0, 1.0, 2.0)).at(16).det_random, 6.0},
      // The JSON report carries the same det ratio the gate reads.
      {"the JSON report's det ratio",
       JsonReport(FakeRatios(1.0, 1.0, 2.0), true)["sizes"]["256"]["det"].get<double>(), 2.0},
      // The medians are under the microsecond key the benchmarks are registered in.
      {"the JSON report's median CPU time",
       JsonReport(FakeRatios(2.0, 1.0, 1.0), true)["sizes"]["16"]["median_cpu_us"]["gcm_seal_random"]
           .get<double>(),
       2.0},
  };
  const auto wrong_verdicts = std::count_if(
      verdicts.begin(), verdicts.end(), [](const std::tuple<std::string, bool, bool> &one) {
        return std::get<1>(one) != std::get<2>(one);
      });
  const auto wrong_ratios = std::count_if(
      ratios.begin(), ratios.end(), [](const std::tuple<std::string, double, double> &one) {
        return std::get<1>(one) != std::get<2>(one);
      });
  const auto wrong = wrong_verdicts + wrong_ratios;
  const auto total = verdicts.size() + ratios.size();
  std::cerr << "bench self-test: " << (total - static_cast<size_t>(wrong)) << " of " << total
            << " verdicts as expected\n";
  return wrong == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--self-test") return SelfTest();
  }

  Require(gcm_init() == GCM_OK, "gcm_init failed: OpenSSL 3 has no AES-GCM provider");
  g_bare = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  Require(g_bare != nullptr, "EVP_CIPHER_fetch(AES-256-GCM) failed");
  g_bare_hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  Require(g_bare_hmac != nullptr, "EVP_MAC_fetch(HMAC) failed");
  // The bare det baseline must seal exactly what the core seals, or the det ratio is meaningless.
  RequireBareDetMatchesCore();

  benchmark::Initialize(&argc, argv);
  for (const int64_t size : kSizes) {
    benchmark::RegisterBenchmark("gcm_seal_random", BM_GcmSealRandom)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
    benchmark::RegisterBenchmark("gcm_seal_det", BM_GcmSealDet)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
    benchmark::RegisterBenchmark("gcm_open", BM_GcmOpen)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
    benchmark::RegisterBenchmark("evp_seal", BM_EvpSeal)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
    benchmark::RegisterBenchmark("evp_seal_det", BM_EvpSealDet)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
    benchmark::RegisterBenchmark("evp_open", BM_EvpOpen)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond)
        ->Repetitions(kRepetitions);
  }

  Collector collector;
  benchmark::RunSpecifiedBenchmarks(&collector);
  benchmark::Shutdown();

  const CpuTimes medians = Medians(collector);
  const bool passed = GateVerdict(medians, LoadCeilings(), &std::cerr);
  // The JSON is written before the verdict is acted on, so a failing run's numbers survive.
  const char *json_path = std::getenv("PG_GCM_BENCH_JSON");
  if (json_path != nullptr && json_path[0] != '\0') WriteJson(medians, passed, json_path);
  if (!passed) {
    Fail("a ratio was above its ceiling");
  }
  std::cerr << "bench: gate passed\n";
  return 0;
}

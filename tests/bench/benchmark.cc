// SPDX-License-Identifier: PostgreSQL
// Core micro-benchmarks (Google Benchmark) for src/gcm.c and its envelope, against bare
// OpenSSL EVP. What is measured is CPU time per call, but the gate is a ratio: the core's
// seal and open over a hand-rolled EVP AES-256-GCM of the same shape, and the deterministic
// seal over the random one. The ceilings live in tests/bench/baseline.json.
//
//     pg_gcm_bench              run every benchmark and gate the ratios
//     pg_gcm_bench --self-test  check the gate itself, with fixed ratios and no crypto
//
// No server and no PostgreSQL header: the core is linked in, as in the unit suite.
#include <benchmark/benchmark.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

extern "C" {
#include "gcm.h"
}

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
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

// The plaintext sizes; larger than one AES block so the ratio is not all per-call overhead.
const std::vector<int64_t> kSizes = {16, 256, 4096, 65536};

const EVP_CIPHER *g_bare = nullptr;

[[noreturn]] void Fail(const std::string &why) {
  std::cerr << "bench: " << why << "\n";
  std::exit(2);
}

// A precondition the measurement cannot proceed without. Named so a benchmark body has no `if`.
void Require(bool ok, const std::string &why) {
  if (!ok) Fail(why);
}

// A raw AES-256-GCM seal through EVP alone: a random nonce, a context, one byte of associated
// data, the plaintext, the tag. The nonce is random so the seal ratio charges the core for its
// own envelope and checks, not for RAND_bytes — the extension draws a random nonce and the
// baseline now draws one too, so the two sides pay it alike. This is "bare EVP" for the seal.
void EvpSeal(const EVP_CIPHER *cipher, const uint8_t *pt, size_t pt_len, uint8_t *ct,
             uint8_t *tag, uint8_t *nonce) {
  Require(RAND_bytes(nonce, GCM_NONCE_LEN) == 1, "RAND_bytes failed");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  Require(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
  int n = 0;
  int fin = 0;
  Require(EVP_EncryptInit_ex2(ctx, cipher, kKey.data(), nonce, nullptr) == 1, "init");
  Require(EVP_EncryptUpdate(ctx, nullptr, &n, &kVersion, 1) == 1, "associated data");
  n = 0;
  Require(EVP_EncryptUpdate(ctx, ct, &n, pt, static_cast<int>(pt_len)) == 1, "update");
  Require(EVP_EncryptFinal_ex(ctx, ct + n, &fin) == 1, "final");
  Require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, tag) == 1, "get tag");
  EVP_CIPHER_CTX_free(ctx);
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

// Captures the CPU time of every run, per iteration, for the ratios.
class Collector : public benchmark::BenchmarkReporter {
 public:
  bool ReportContext(const Context & /*context*/) override { return true; }
  void ReportRuns(const std::vector<Run> &runs) override {
    // run_name.str() is the full name with the argument ("gcm_seal_random/16"), which is the
    // key the gate looks up; the bare benchmark_name() has no argument.
    for (const Run &run : runs) cpu_ns_[run.run_name.str()] = run.GetAdjustedCPUTime();
  }
  void Finalize() override {}

  const std::map<std::string, double> &cpu_ns() const { return cpu_ns_; }

 private:
  std::map<std::string, double> cpu_ns_;
};

double Measure(const Collector &collector, const std::string &name) {
  const auto &times = collector.cpu_ns();
  const auto found = times.find(name);
  Require(found != times.end(), "no measurement for " + name);
  return found->second;
}

double Ratio(const Collector &collector, const std::string &numerator,
             const std::string &denominator) {
  return RatioOf(Measure(collector, numerator), Measure(collector, denominator));
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
  };
  // name, the ratio RatioOf gives, and the ratio it must give. Swapping the gate's numerator and
  // denominator would turn 2.0 into 0.5 and let a regression pass, so the direction is pinned.
  const std::vector<std::tuple<std::string, double, double>> ratios = {
      {"the two sides equal", RatioOf(1.0, 1.0), 1.0},
      {"the core twice the baseline", RatioOf(2.0, 1.0), 2.0},
      {"the core half the baseline", RatioOf(1.0, 2.0), 0.5},
      {"a zero denominator is infinite", RatioOf(1.0, 0.0),
       std::numeric_limits<double>::infinity()},
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

void Gate(const Collector &collector) {
  const std::map<int64_t, Ceilings> ceilings = LoadCeilings();
  bool passed = true;
  for (const int64_t size : kSizes) {
    const std::string at = "/" + std::to_string(size);
    const auto found = ceilings.find(size);
    Require(found != ceilings.end(), "no ceiling for " + std::to_string(size) + " bytes");
    const Ceilings &ceiling = found->second;
    const double seal = Ratio(collector, "gcm_seal_random" + at, "evp_seal" + at);
    const double open = Ratio(collector, "gcm_open" + at, "evp_open" + at);
    const double det = Ratio(collector, "gcm_seal_det" + at, "gcm_seal_random" + at);
    passed = Passes(seal, open, det, ceiling) && passed;
    std::cerr << size << " bytes: seal " << seal << " (<= " << ceiling.seal << "), open " << open
              << " (<= " << ceiling.open << "), det " << det << " (<= " << ceiling.det << ")\n";
  }
  std::cerr << "bench: gate " << (passed ? "passed" : "failed") << "\n";
  if (!passed) Fail("a ratio was above its ceiling");
}

}  // namespace

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--self-test") return SelfTest();
  }

  Require(gcm_init() == GCM_OK, "gcm_init failed: OpenSSL 3 has no AES-GCM provider");
  g_bare = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  Require(g_bare != nullptr, "EVP_CIPHER_fetch(AES-256-GCM) failed");

  benchmark::Initialize(&argc, argv);
  for (const int64_t size : kSizes) {
    benchmark::RegisterBenchmark("gcm_seal_random", BM_GcmSealRandom)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond);
    benchmark::RegisterBenchmark("gcm_seal_det", BM_GcmSealDet)
        ->Arg(size)
        ->Unit(benchmark::kMicrosecond);
    benchmark::RegisterBenchmark("gcm_open", BM_GcmOpen)->Arg(size)->Unit(benchmark::kMicrosecond);
    benchmark::RegisterBenchmark("evp_seal", BM_EvpSeal)->Arg(size)->Unit(benchmark::kMicrosecond);
    benchmark::RegisterBenchmark("evp_open", BM_EvpOpen)->Arg(size)->Unit(benchmark::kMicrosecond);
  }

  Collector collector;
  benchmark::RunSpecifiedBenchmarks(&collector);
  benchmark::Shutdown();

  Gate(collector);
  return 0;
}

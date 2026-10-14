// SPDX-License-Identifier: PostgreSQL
#include <cstdio>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/err.h>

#include "alloc_counter.h"
#include "test_util.h"

namespace {

// OpenSSL allocates some things once per process or thread and keeps them: the DRBGs behind
// RAND_bytes, the thread's error state, provider caches. Exercise every operation, and every
// allocation failure inside it, before any test takes a baseline, so that what a test counts
// is what its own call left behind.
void WarmUp() {
  const Bytes key = PatternKey();
  const Bytes pt = Utf8("warm-up");
  const Bytes aad = Utf8("warm-up aad");
  Bytes env = EnvelopeBuffer(pt.size());
  Bytes out = PlaintextBuffer(pt.size());
  size_t n = 0;

  for (int round = 0; round < 2; ++round) {
    for (long nth = 0; nth <= 40; ++nth) {
      alloc_counter::FailNth(nth);
      (void)gcm_seal(key.data(), key.size(), aad.data(), aad.size(), pt.data(), pt.size(), 0,
                     env.data(), env.size());
      alloc_counter::FailNth(nth);
      (void)gcm_seal(key.data(), key.size(), aad.data(), aad.size(), pt.data(), pt.size(), 1,
                     env.data(), env.size());
      alloc_counter::FailNone();
      (void)gcm_seal(key.data(), key.size(), aad.data(), aad.size(), pt.data(), pt.size(), 0,
                     env.data(), env.size());
      alloc_counter::FailNth(nth);
      (void)gcm_open(key.data(), key.size(), aad.data(), aad.size(), env.data(), env.size(),
                     out.data(), out.size(), &n);
      alloc_counter::FailNone();
    }
  }
  ERR_clear_error();
}

}  // namespace

int main(int argc, char **argv) {
  // First, before any OpenSSL call: once OpenSSL has allocated, CRYPTO_set_mem_functions
  // returns 0 and the counter would count nothing. A test asserts the value as well.
  if (alloc_counter::Install() != 1) {
    std::fprintf(stderr, "CRYPTO_set_mem_functions did not return 1; nothing would be counted\n");
    return 2;
  }
  if (gcm_init() != GCM_OK) {
    std::fprintf(stderr, "gcm_init could not fetch the AES-GCM ciphers and HMAC\n");
    return 2;
  }
  WarmUp();

  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}

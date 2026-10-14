// SPDX-License-Identifier: PostgreSQL
// A second executable that never calls gcm_init: the state a backend is in when the fetch in
// _PG_init failed (docs/design.md §5.8). Every call must then fail with the OpenSSL error
// class, and nothing else.
#include <gtest/gtest.h>

#include "test_util.h"

namespace {

TEST(NoHandles, GivenFetchNeverRan_WhenAskedIfReady_ThenNotReady) {
  // Given: no gcm_init in this process

  // When
  const int ready = gcm_ready();

  // Then
  EXPECT_EQ(ready, 0);
}

TEST(NoHandles, GivenFetchNeverRan_WhenSealedRandom_ThenOpenSslFailure) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                plaintext.size(), 0, envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

TEST(NoHandles, GivenFetchNeverRan_WhenSealedDeterministic_ThenOpenSslFailure) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                plaintext.size(), 1, envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

TEST(NoHandles, GivenFetchNeverRan_WhenOpened_ThenOpenSslFailureAndOutputCleansed) {
  // Given: 45 bytes with a valid version byte; without handles nothing looks further
  const Bytes key = ZeroKey();
  Bytes envelope(45, 0);
  envelope[0] = GCM_V_AES256_RANDOM;
  Bytes out = PlaintextBuffer(16);
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(key.data(), key.size(), nullptr, 0, envelope.data(),
                                envelope.size(), out.data(), out.size(), &out_len);

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
  EXPECT_EQ(out_len, 0u);
  EXPECT_EQ(out, Bytes(out.size(), 0));
}

}  // namespace

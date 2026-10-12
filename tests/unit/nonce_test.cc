// SPDX-License-Identifier: PostgreSQL
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "test_util.h"

extern "C" {
#include "nonce.h"
}

namespace {

struct NonceVector {
  const char *name;
  const char *plaintext_hex;
  const char *nonce_hex;
};

// Known answers from an implementation that is not the one under test — Python's hmac module:
//   nonce_key = hmac.new(bytes(range(32)), b"pg_gcm/v1/det-nonce", sha256).digest()
//   nonce     = hmac.new(nonce_key, plaintext, sha256).digest()[:12]
// They move to spec/test-vectors.json in Phase 1.
const NonceVector kVectors[] = {
    {"Empty", "", "13bae553d5ada4dd1e8a959f"},
    {"OneAsciiByte", "78", "a3eeccbe8faab5678f532939"},
    {"KoreanName", "ed998deab8b8eb8f99", "f55369153b2a94fcbc9b633f"},
};

class DetNonce : public ::testing::TestWithParam<NonceVector> {
 protected:
  static void SetUpTestSuite() { hmac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr); }
  static void TearDownTestSuite() { EVP_MAC_free(hmac_); }
  static EVP_MAC *hmac_;
};
EVP_MAC *DetNonce::hmac_ = nullptr;

TEST_P(DetNonce, GivenPatternKeyAndPlaintext_WhenDerived_ThenNonceIsTheKnownAnswer) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Hex(GetParam().plaintext_hex);
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc = gcm_nonce_derive(hmac_, key.data(), key.size(), plaintext.data(),
                                        plaintext.size(), nonce.data());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(nonce, Hex(GetParam().nonce_hex));
}

INSTANTIATE_TEST_SUITE_P(KnownAnswers, DetNonce, ::testing::ValuesIn(kVectors),
                         [](const auto &info) { return std::string(info.param.name); });

TEST(DetNonceHandle, GivenEmptyKey_WhenDerived_ThenOpenSslFailure) {
  // Given
  EVP_MAC *hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("x");
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc =
      gcm_nonce_derive(hmac, key.data(), 0, plaintext.data(), plaintext.size(), nonce.data());
  EVP_MAC_free(hmac);

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

TEST(DetNonceHandle, GivenNoHmacHandle_WhenDerived_ThenOpenSslFailure) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("x");
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc = gcm_nonce_derive(nullptr, key.data(), key.size(), plaintext.data(),
                                        plaintext.size(), nonce.data());

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

}  // namespace

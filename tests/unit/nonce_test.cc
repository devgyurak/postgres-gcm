// SPDX-License-Identifier: PostgreSQL
// gcm_nonce_derive on its own: the nonce of every deterministic vector of
// spec/test-vectors.json whose nonce is derived, and what the function refuses.
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "vectors.h"

extern "C" {
#include "nonce.h"
}

namespace {

class DerivedNonce : public ::testing::TestWithParam<Vector> {};

// The version byte of the vector's envelope is the first byte of the associated data (spec 1.8).
TEST_P(DerivedNonce, GivenVectorsKeyAadAndPlaintext_WhenNonceDerived_ThenItIsTheVectorsNonce) {
  // Given
  const Vector &v = GetParam();
  EVP_MAC *hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc =
      gcm_nonce_derive(hmac, v.key.data(), v.key.size(), v.envelope[0], v.aad.data(),
                       v.aad.size(), v.plaintext.data(), v.plaintext.size(), nonce.data());
  EVP_MAC_free(hmac);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(nonce, v.nonce);
}

INSTANTIATE_TEST_SUITE_P(Spec, DerivedNonce, ::testing::ValuesIn(DerivedSealVectors()), VectorName);

TEST(DetNonce, GivenNoHmacHandle_WhenDerived_ThenOpenSslFailure) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("x");
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc =
      gcm_nonce_derive(nullptr, key.data(), key.size(), GCM_V_AES256_DET, nullptr, 0,
                       plaintext.data(), plaintext.size(), nonce.data());

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

TEST(DetNonce, GivenEmptyKey_WhenDerived_ThenBadKeyLen) {
  // Given
  EVP_MAC *hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("x");
  Bytes nonce(GCM_NONCE_LEN, 0);

  // When
  const gcm_error rc = gcm_nonce_derive(hmac, key.data(), 0, GCM_V_AES256_DET, nullptr, 0,
                                        plaintext.data(), plaintext.size(), nonce.data());
  EVP_MAC_free(hmac);

  // Then: no key is a key-length error, whether or not there is a handle to use it with
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
}

}  // namespace

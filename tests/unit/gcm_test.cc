// SPDX-License-Identifier: PostgreSQL
#include <gtest/gtest.h>

#include "test_util.h"

namespace {

// ---- Known answers ---------------------------------------------------------------------------

struct GcmVector {
  const char *name;
  const char *key_hex;
  const char *nonce_hex;
  const char *plaintext_hex;
  const char *envelope_hex;  // 0x02 || nonce || ciphertext || tag
};

// AES-256 cases with a 96-bit IV and no AAD from the GCM specification's test vectors
// (McGrew and Viega, test cases 13 and 14). They move to spec/test-vectors.json in Phase 1.
const GcmVector kVectors[] = {
    {"TestCase13EmptyPlaintext",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", "",
     "02000000000000000000000000530f8afbc74536b9a963b4f1c4cb738b"},
    {"TestCase14OneZeroBlock",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", "00000000000000000000000000000000",
     "02000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"},
};

class GcmKnownAnswer : public ::testing::TestWithParam<GcmVector> {};

TEST_P(GcmKnownAnswer, GivenVectorKeyNonceAndPlaintext_WhenSealed_ThenEnvelopeIsTheKnownAnswer) {
  // Given
  const Bytes key = Hex(GetParam().key_hex);
  const Bytes nonce = Hex(GetParam().nonce_hex);
  const Bytes plaintext = Hex(GetParam().plaintext_hex);
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc =
      gcm_seal_with_nonce(key.data(), key.size(), nonce.data(), GCM_V_AES256_RANDOM,
                          plaintext.data(), plaintext.size(), envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(envelope, Hex(GetParam().envelope_hex));
}

TEST_P(GcmKnownAnswer, GivenVectorEnvelope_WhenOpened_ThenPlaintextIsTheKnownAnswer) {
  // Given
  const Bytes key = Hex(GetParam().key_hex);
  const Bytes envelope = Hex(GetParam().envelope_hex);
  const Bytes expected = Hex(GetParam().plaintext_hex);
  Bytes out = PlaintextBuffer(expected.size());
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(key.data(), key.size(), envelope.data(), envelope.size(),
                                out.data(), out.size(), &out_len);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + static_cast<long>(out_len)), expected);
}

INSTANTIATE_TEST_SUITE_P(Spec, GcmKnownAnswer, ::testing::ValuesIn(kVectors),
                         [](const auto &info) { return std::string(info.param.name); });

// ---- Round trips -----------------------------------------------------------------------------

class RoundTrip : public ::testing::TestWithParam<std::tuple<std::string, int>> {};

TEST_P(RoundTrip, GivenSealedPlaintext_WhenOpenedWithTheSameKey_ThenPlaintextReturns) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8(std::get<0>(GetParam()));
  Bytes envelope = EnvelopeBuffer(plaintext.size());
  ASSERT_EQ(gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(),
                     std::get<1>(GetParam()), envelope.data(), envelope.size()),
            GCM_OK);
  Bytes out = PlaintextBuffer(plaintext.size());
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(key.data(), key.size(), envelope.data(), envelope.size(),
                                out.data(), out.size(), &out_len);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + static_cast<long>(out_len)), plaintext);
}

INSTANTIATE_TEST_SUITE_P(Plaintexts, RoundTrip,
                         ::testing::Combine(::testing::Values("", "a", "홍길동",
                                                              std::string(4096, 'x')),
                                            ::testing::Values(0, 1)),
                         [](const auto &info) {
                           return "Plaintext" + std::to_string(info.index / 2) +
                                  (std::get<1>(info.param) ? "Deterministic" : "Random");
                         });

TEST(GcmSeal, GivenRandomVariant_WhenSealed_ThenVersionIs02AndLengthIsPlaintextPlus29) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 0,
                                envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(envelope[0], 0x02);
  EXPECT_EQ(envelope.size(), plaintext.size() + 29);
}

TEST(GcmSeal, GivenRandomVariant_WhenSealedTwice_ThenEnvelopesDiffer) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes first = EnvelopeBuffer(plaintext.size());
  Bytes second = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc1 = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 0,
                                 first.data(), first.size());
  const gcm_error rc2 = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 0,
                                 second.data(), second.size());

  // Then
  EXPECT_EQ(rc1, GCM_OK);
  EXPECT_EQ(rc2, GCM_OK);
  EXPECT_NE(first, second);
}

TEST(GcmSeal, GivenDeterministicVariant_WhenSealedTwice_ThenEnvelopesAreEqualWithVersion03) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes first = EnvelopeBuffer(plaintext.size());
  Bytes second = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc1 = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 1,
                                 first.data(), first.size());
  const gcm_error rc2 = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 1,
                                 second.data(), second.size());

  // Then
  EXPECT_EQ(rc1, GCM_OK);
  EXPECT_EQ(rc2, GCM_OK);
  EXPECT_EQ(first, second);
  EXPECT_EQ(first[0], 0x03);
}

TEST(GcmSeal, GivenDeterministicVariant_WhenSealed_ThenNonceIsTheKnownAnswer) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 1,
                                envelope.data(), envelope.size());

  // Then (the nonce is nonce_test.cc's Python-derived answer for this plaintext)
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(envelope.begin() + 1, envelope.begin() + 13), Hex("f55369153b2a94fcbc9b633f"));
}

TEST(GcmSeal, GivenOutputBufferOfTheWrongSize_WhenSealed_ThenBadLength) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size() + 1);

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), plaintext.data(), plaintext.size(), 0,
                                envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
}

}  // namespace

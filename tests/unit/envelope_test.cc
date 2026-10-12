// SPDX-License-Identifier: PostgreSQL
#include <gtest/gtest.h>

#include "test_util.h"

namespace {

class TruncatedEnvelope : public ::testing::TestWithParam<size_t> {};

TEST_P(TruncatedEnvelope, GivenFewerThan29Bytes_WhenParsed_ThenBadEnvelope) {
  // Given
  Bytes env(29, 0);
  env[0] = GCM_V_AES256_RANDOM;
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), GetParam(), &view);

  // Then
  EXPECT_EQ(rc, GCM_BAD_ENVELOPE);
}

INSTANTIATE_TEST_SUITE_P(Lengths, TruncatedEnvelope, ::testing::Values(0u, 1u, 12u, 28u));

class UnopenedVersion : public ::testing::TestWithParam<int> {};

// Phase S opens AES-256 only: 0x04..0x07 are allocated, and join the opened set in Phase 2.
TEST_P(UnopenedVersion, GivenVersionByteThisBuildDoesNotOpen_WhenParsed_ThenBadEnvelope) {
  // Given
  Bytes env(29, 0);
  env[0] = static_cast<uint8_t>(GetParam());
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), env.size(), &view);

  // Then
  EXPECT_EQ(rc, GCM_BAD_ENVELOPE);
}

INSTANTIATE_TEST_SUITE_P(Versions, UnopenedVersion,
                         ::testing::Values(0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff));

TEST(Envelope, GivenMinimalEnvelope_WhenParsed_ThenEmptyCiphertextAndFieldsAtSpecOffsets) {
  // Given
  Bytes env(29, 0);
  env[0] = GCM_V_AES256_DET;
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), env.size(), &view);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(view.version, GCM_V_AES256_DET);
  EXPECT_EQ(view.nonce, env.data() + 1);
  EXPECT_EQ(view.ciphertext_len, 0u);
  EXPECT_EQ(view.tag, env.data() + 13);
}

TEST(Envelope, GivenEnvelopeOfNinePlaintextBytes_WhenParsed_ThenCiphertextAt13AndTagAt22) {
  // Given
  Bytes env(38, 0);
  env[0] = GCM_V_AES256_RANDOM;
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), env.size(), &view);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(view.ciphertext, env.data() + 13);
  EXPECT_EQ(view.ciphertext_len, 9u);
  EXPECT_EQ(view.tag, env.data() + 22);
}

TEST(Envelope, GivenNullInput_WhenParsed_ThenBadEnvelope) {
  // Given
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(nullptr, 0, &view);

  // Then
  EXPECT_EQ(rc, GCM_BAD_ENVELOPE);
}

TEST(Envelope, GivenNoViewToFill_WhenParsed_ThenBadEnvelope) {
  // Given
  Bytes env(29, 0);
  env[0] = GCM_V_AES256_RANDOM;

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), env.size(), nullptr);

  // Then
  EXPECT_EQ(rc, GCM_BAD_ENVELOPE);
}

TEST(Envelope, Given32ByteKey_WhenVersionChosen_ThenRandomIs02AndDeterministicIs03) {
  // Given
  const size_t key_len = 32;

  // When
  const uint8_t random = gcm_version_for(key_len, 0);
  const uint8_t det = gcm_version_for(key_len, 1);

  // Then
  EXPECT_EQ(random, 0x02);
  EXPECT_EQ(det, 0x03);
}

}  // namespace

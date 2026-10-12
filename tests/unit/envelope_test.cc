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

// 0x01 is reserved for the legacy format and is not opened; nothing above 0x07 is allocated.
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

INSTANTIATE_TEST_SUITE_P(Versions, UnopenedVersion, ::testing::Values(0x00, 0x01, 0x08, 0xff));

struct VersionCase {
  const char *name;
  uint8_t version;
  size_t key_len;
  int deterministic;
};

const VersionCase kVersions[] = {
    {"V02", 0x02, 32, 0}, {"V03", 0x03, 32, 1}, {"V04", 0x04, 16, 0},
    {"V05", 0x05, 16, 1}, {"V06", 0x06, 24, 0}, {"V07", 0x07, 24, 1},
};

class OpenedVersion : public ::testing::TestWithParam<VersionCase> {};

TEST_P(OpenedVersion, GivenAllocatedVersionByte_WhenParsed_ThenAcceptedWithItsKeyLength) {
  // Given
  Bytes env(29, 0);
  env[0] = GetParam().version;
  gcm_envelope_view view{};

  // When
  const gcm_error rc = gcm_envelope_parse(env.data(), env.size(), &view);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(view.version, GetParam().version);
  EXPECT_EQ(gcm_version_key_len(view.version), GetParam().key_len);
}

TEST_P(OpenedVersion, GivenKeyLengthAndVariant_WhenVersionChosen_ThenItIsTheSuitesByte) {
  // Given
  const VersionCase c = GetParam();

  // When
  const uint8_t version = gcm_version_for(c.key_len, c.deterministic);

  // Then
  EXPECT_EQ(version, c.version);
}

INSTANTIATE_TEST_SUITE_P(Versions, OpenedVersion, ::testing::ValuesIn(kVersions),
                         [](const auto &info) { return std::string(info.param.name); });

class NoSuiteKeyLength : public ::testing::TestWithParam<size_t> {};

TEST_P(NoSuiteKeyLength, GivenKeyLengthThatNamesNoSuite_WhenVersionChosen_ThenZero) {
  // Given
  const size_t key_len = GetParam();

  // When
  const uint8_t version = gcm_version_for(key_len, 0);

  // Then
  EXPECT_EQ(version, 0);
}

INSTANTIATE_TEST_SUITE_P(Lengths, NoSuiteKeyLength, ::testing::Values(0u, 15u, 20u, 31u, 33u, 64u));

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

}  // namespace

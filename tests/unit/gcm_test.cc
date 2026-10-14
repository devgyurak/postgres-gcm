// SPDX-License-Identifier: PostgreSQL
// The contract of seal and open that no vector states: properties of the random variant,
// the buffers a caller hands over, and the lengths that are refused. The known answers are
// in vectors_test.cc, read from spec/test-vectors.json.
#include <gtest/gtest.h>

#include "test_util.h"

namespace {

// ---- Round trips -----------------------------------------------------------------------------

struct RoundTripCase {
  const char *name;
  size_t key_len;
  int deterministic;
  std::string plaintext;
  std::string aad;
};

const RoundTripCase kRoundTrips[] = {
    {"Aes256RandomEmpty", 32, 0, "", ""},
    {"Aes256RandomKorean", 32, 0, "홍길동", ""},
    {"Aes256RandomKoreanWithAad", 32, 0, "홍길동", "patients.name"},
    {"Aes256DeterministicKoreanWithAad", 32, 1, "홍길동", "patients.name"},
    {"Aes256RandomFourKilobytes", 32, 0, std::string(4096, 'x'), ""},
    {"Aes192RandomKorean", 24, 0, "홍길동", ""},
    {"Aes192DeterministicKorean", 24, 1, "홍길동", ""},
    {"Aes128RandomKoreanWithAad", 16, 0, "홍길동", "patients.name"},
    {"Aes128DeterministicEmpty", 16, 1, "", ""},
};

class RoundTrip : public ::testing::TestWithParam<RoundTripCase> {};

TEST_P(RoundTrip, GivenSealedPlaintext_WhenOpenedWithTheSameKeyAndAad_ThenPlaintextReturns) {
  // Given
  const Bytes key = KeyOfLength(GetParam().key_len);
  const Bytes plaintext = Utf8(GetParam().plaintext);
  const Bytes aad = Utf8(GetParam().aad);
  Bytes envelope = EnvelopeBuffer(plaintext.size());
  ASSERT_EQ(gcm_seal(key.data(), GetParam().key_len, aad.data(), aad.size(), plaintext.data(),
                     plaintext.size(), GetParam().deterministic, envelope.data(),
                     envelope.size()),
            GCM_OK);
  Bytes out = PlaintextBuffer(plaintext.size());
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(key.data(), GetParam().key_len, aad.data(), aad.size(),
                                envelope.data(), envelope.size(), out.data(), out.size(), &out_len);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + static_cast<long>(out_len)), plaintext);
}

INSTANTIATE_TEST_SUITE_P(Suites, RoundTrip, ::testing::ValuesIn(kRoundTrips),
                         [](const auto &info) { return std::string(info.param.name); });

// ---- The key length selects the suite ----------------------------------------------------------

struct SuiteCase {
  const char *name;
  size_t key_len;
  int deterministic;
  uint8_t version;
};

const SuiteCase kSuites[] = {
    {"Aes256Random", 32, 0, 0x02}, {"Aes256Deterministic", 32, 1, 0x03},
    {"Aes128Random", 16, 0, 0x04}, {"Aes128Deterministic", 16, 1, 0x05},
    {"Aes192Random", 24, 0, 0x06}, {"Aes192Deterministic", 24, 1, 0x07},
};

class Suite : public ::testing::TestWithParam<SuiteCase> {};

TEST_P(Suite, GivenKeyLengthAndVariant_WhenSealed_ThenVersionByteNamesThemAndLengthIsPlus29) {
  // Given
  const Bytes key = KeyOfLength(GetParam().key_len);
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), GetParam().key_len, nullptr, 0, plaintext.data(),
                                plaintext.size(), GetParam().deterministic, envelope.data(),
                                envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(envelope[0], GetParam().version);
  EXPECT_EQ(envelope.size(), plaintext.size() + 29);
}

INSTANTIATE_TEST_SUITE_P(Suites, Suite, ::testing::ValuesIn(kSuites),
                         [](const auto &info) { return std::string(info.param.name); });

class RefusedKeyLength : public ::testing::TestWithParam<size_t> {};

TEST_P(RefusedKeyLength, GivenKeyLengthThatNamesNoSuite_WhenSealed_ThenBadKeyLen) {
  // Given
  const Bytes key = KeyOfLength(GetParam());
  const Bytes plaintext = Utf8("x");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal(key.data(), GetParam(), nullptr, 0, plaintext.data(),
                                plaintext.size(), 0, envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
}

INSTANTIATE_TEST_SUITE_P(Lengths, RefusedKeyLength,
                         ::testing::Values(0u, 15u, 17u, 23u, 25u, 31u, 33u));

class AcceptedKeyLength : public ::testing::TestWithParam<size_t> {};

TEST_P(AcceptedKeyLength, GivenSuiteKeyLength_WhenAsked_ThenSupported) {
  // Given
  const size_t key_len = GetParam();

  // When
  const int supported = gcm_key_len_supported(key_len);

  // Then
  EXPECT_EQ(supported, 1);
}

INSTANTIATE_TEST_SUITE_P(Lengths, AcceptedKeyLength, ::testing::Values(16u, 24u, 32u));

// ---- The random variant ------------------------------------------------------------------------

TEST(GcmSeal, GivenRandomVariant_WhenSealedTwice_ThenEnvelopesDiffer) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes first = EnvelopeBuffer(plaintext.size());
  Bytes second = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc1 = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                 plaintext.size(), 0, first.data(), first.size());
  const gcm_error rc2 = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                 plaintext.size(), 0, second.data(), second.size());

  // Then
  EXPECT_EQ(rc1, GCM_OK);
  EXPECT_EQ(rc2, GCM_OK);
  EXPECT_NE(first, second);
}

// ---- What a caller hands over ------------------------------------------------------------------

TEST(GcmSeal, GivenOutputBufferOfTheWrongSize_WhenSealed_ThenBadLength) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size() + 1);

  // When
  const gcm_error rc = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                plaintext.size(), 0, envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
}

// A null buffer is refused for itself, before any arithmetic on it.
TEST(GcmSeal, GivenNullOutputBufferOfTheRightStatedSize_WhenSealed_ThenBadLength) {
  // Given
  const Bytes key = PatternKey();
  const Bytes plaintext = Utf8("홍길동");

  // When
  const gcm_error random = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                    plaintext.size(), 0, nullptr,
                                    plaintext.size() + GCM_ENVELOPE_OVERHEAD);
  const gcm_error det = gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(),
                                 plaintext.size(), 1, nullptr,
                                 plaintext.size() + GCM_ENVELOPE_OVERHEAD);

  // Then
  EXPECT_EQ(random, GCM_BAD_LENGTH);
  EXPECT_EQ(det, GCM_BAD_LENGTH);
}

TEST(GcmSealWithNonce, GivenVersionByteOfAnotherSuite_WhenSealed_ThenBadKeyLen) {
  // Given: a 32-byte key with the AES-128 version byte
  const Bytes key = PatternKey();
  const Bytes nonce(GCM_NONCE_LEN, 0);
  const Bytes plaintext = Utf8("x");
  Bytes envelope = EnvelopeBuffer(plaintext.size());

  // When
  const gcm_error rc = gcm_seal_with_nonce(key.data(), key.size(), nonce.data(),
                                           GCM_V_AES128_RANDOM, nullptr, 0, plaintext.data(),
                                           plaintext.size(), envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
}

// A valid envelope and buffers that start as 0xAA, so that a cleanse is visible.
struct Opened {
  Bytes key = PatternKey();
  Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());
  Bytes out = PlaintextBuffer(plaintext.size());
  size_t out_len = 99;

  Opened() {
    (void)gcm_seal(key.data(), key.size(), nullptr, 0, plaintext.data(), plaintext.size(), 0,
                   envelope.data(), envelope.size());
  }
};

TEST(GcmOpen, GivenNowhereToReportTheLength_WhenOpened_ThenBadLengthAndOutputCleansed) {
  // Given
  Opened o;

  // When
  const gcm_error rc = gcm_open(o.key.data(), o.key.size(), nullptr, 0, o.envelope.data(),
                                o.envelope.size(), o.out.data(), o.out.size(), nullptr);

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
  EXPECT_EQ(o.out, Bytes(o.out.size(), 0));
}

TEST(GcmOpen, GivenOutputBufferSmallerThanThePlaintext_WhenOpened_ThenBadLengthAndCleansed) {
  // Given
  Opened o;
  o.out = Bytes(o.plaintext.size() - 1, 0xAA);

  // When
  const gcm_error rc = gcm_open(o.key.data(), o.key.size(), nullptr, 0, o.envelope.data(),
                                o.envelope.size(), o.out.data(), o.out.size(), &o.out_len);

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
  EXPECT_EQ(o.out_len, 0u);
  EXPECT_EQ(o.out, Bytes(o.out.size(), 0));
}

// A null buffer is refused for itself, not because its stated capacity is too small.
TEST(GcmOpen, GivenNullBufferOfSufficientStatedCapacity_WhenOpened_ThenBadLength) {
  // Given
  Opened o;

  // When
  const gcm_error rc = gcm_open(o.key.data(), o.key.size(), nullptr, 0, o.envelope.data(),
                                o.envelope.size(), nullptr, o.plaintext.size(), &o.out_len);

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
  EXPECT_EQ(o.out_len, 0u);
}

TEST(GcmOpen, GivenAadTheEnvelopeWasNotSealedWith_WhenOpened_ThenBadTagAndCleansed) {
  // Given
  Opened o;
  const Bytes aad = Utf8("patients.name");

  // When
  const gcm_error rc = gcm_open(o.key.data(), o.key.size(), aad.data(), aad.size(),
                                o.envelope.data(), o.envelope.size(), o.out.data(), o.out.size(),
                                &o.out_len);

  // Then
  EXPECT_EQ(rc, GCM_BAD_TAG);
  EXPECT_EQ(o.out, Bytes(o.out.size(), 0));
}

TEST(GcmCleanse, GivenBufferOfNonZeroBytes_WhenCleansed_ThenEveryByteIsZero) {
  // Given
  Bytes secret(64, 0xA5);

  // When
  gcm_cleanse(secret.data(), secret.size());

  // Then
  EXPECT_EQ(secret, Bytes(64, 0));
}

}  // namespace

// SPDX-License-Identifier: PostgreSQL
// The core against every vector of spec/test-vectors.json (spec 1.11): a nist vector on the
// primitive, an envelope vector through open, and a valid one through seal as well.
#include <gtest/gtest.h>

#include "vectors.h"

namespace {

std::string Name(const ::testing::TestParamInfo<Vector> &info) {
  std::string name = info.param.id;
  for (char &c : name) {
    if (c == '-') c = '_';
  }
  return name;
}

// A buffer that is never empty, so data() is never null, filled so a cleanse is visible.
Bytes Scratch(size_t n) { return Bytes(n + 1, 0xAA); }

class NistVector : public ::testing::TestWithParam<Vector> {};

TEST_P(NistVector, GivenNistKnownAnswer_WhenThePrimitiveSeals_ThenCiphertextAndTagMatch) {
  // Given
  const Vector &v = GetParam();
  Bytes ciphertext = Scratch(v.plaintext.size());
  Bytes tag(GCM_TAG_LEN, 0);

  // When: the whole associated data is NIST's; this is not an envelope
  const gcm_error rc =
      gcm_aead_seal_raw(v.key.data(), v.key.size(), v.nonce.data(), v.aad.data(), v.aad.size(),
                        v.plaintext.data(), v.plaintext.size(), ciphertext.data(), tag.data());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(ciphertext.begin(), ciphertext.begin() + static_cast<long>(v.plaintext.size())),
            v.ciphertext);
  EXPECT_EQ(tag, v.tag);
}

INSTANTIATE_TEST_SUITE_P(Spec, NistVector, ::testing::ValuesIn(NistVectors()), Name);

class OpeningVector : public ::testing::TestWithParam<Vector> {};

TEST_P(OpeningVector, GivenValidEnvelope_WhenOpened_ThenPlaintextIsTheVectors) {
  // Given
  const Vector &v = GetParam();
  Bytes out = Scratch(v.plaintext.size());
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(v.key.data(), v.key.size(), v.aad.data(), v.aad.size(),
                                v.envelope.data(), v.envelope.size(), out.data(), out.size(),
                                &out_len);

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + static_cast<long>(out_len)), v.plaintext);
}

INSTANTIATE_TEST_SUITE_P(Spec, OpeningVector, ::testing::ValuesIn(OpeningVectors()), Name);

class RandomSealVector : public ::testing::TestWithParam<Vector> {};

TEST_P(RandomSealVector, GivenInputsAndTheVectorsNonce_WhenSealed_ThenEnvelopeIsTheVectors) {
  // Given
  const Vector &v = GetParam();
  Bytes envelope = EnvelopeBuffer(v.plaintext.size());

  // When: through the seam, because a random seal draws its own nonce
  const gcm_error rc = gcm_seal_with_nonce(
      v.key.data(), v.key.size(), v.nonce.data(), v.envelope[0], v.aad.data(), v.aad.size(),
      v.plaintext.data(), v.plaintext.size(), envelope.data(), envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(envelope, v.envelope);
}

INSTANTIATE_TEST_SUITE_P(Spec, RandomSealVector, ::testing::ValuesIn(RandomSealVectors()), Name);

class DerivedSealVector : public ::testing::TestWithParam<Vector> {};

TEST_P(DerivedSealVector, GivenInputsAlone_WhenSealedDeterministic_ThenEnvelopeIsTheVectors) {
  // Given
  const Vector &v = GetParam();
  Bytes envelope = EnvelopeBuffer(v.plaintext.size());

  // When: no nonce is supplied; the core derives it (spec 1.8)
  const gcm_error rc = gcm_seal(v.key.data(), v.key.size(), v.aad.data(), v.aad.size(),
                                v.plaintext.data(), v.plaintext.size(), 1, envelope.data(),
                                envelope.size());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(envelope, v.envelope);
}

INSTANTIATE_TEST_SUITE_P(Spec, DerivedSealVector, ::testing::ValuesIn(DerivedSealVectors()), Name);

class FailingVector : public ::testing::TestWithParam<Vector> {};

TEST_P(FailingVector, GivenEnvelopeThatMustNotOpen_WhenOpened_ThenItsOutcomeAndNothingInTheBuffer) {
  // Given
  const Vector &v = GetParam();
  Bytes out = Scratch(v.envelope.size());
  size_t out_len = 99;

  // When
  const gcm_error rc = gcm_open(v.key.data(), v.key.size(), v.aad.data(), v.aad.size(),
                                v.envelope.data(), v.envelope.size(), out.data(), out.size(),
                                &out_len);

  // Then: the outcome spec 1.7 fixes, and no byte of anything left for the caller
  EXPECT_EQ(rc, ExpectedError(v));
  EXPECT_EQ(out_len, 0u);
  EXPECT_EQ(out, Bytes(out.size(), 0));
}

INSTANTIATE_TEST_SUITE_P(Spec, FailingVector, ::testing::ValuesIn(FailingVectors()), Name);

// A vector that no suite consumes would be a vector that proves nothing. The loader refuses a
// kind or an expect it does not know, so a vector cannot slip between the selections.
TEST(VectorFile, GivenTheWholeFile_WhenSplitAmongTheSuites_ThenEveryVectorIsRunExactlyOnce) {
  // Given
  const std::vector<std::string> all = SortedIds({AllVectors()});

  // When: what the three suites that run a vector are parameterised over
  const std::vector<std::string> run =
      SortedIds({NistVectors(), OpeningVectors(), FailingVectors()});

  // Then
  EXPECT_FALSE(all.empty());
  EXPECT_EQ(run, all);
}

TEST(VectorFile, GivenTheEnvelopesThatOpen_WhenSplitAmongTheSealingSuites_ThenOnlyTheNotDerivedAreLeftOut) {
  // Given
  const std::vector<std::string> opening = SortedIds({OpeningVectors()});

  // When: the two suites that seal, and the vectors marked as ones no sealer can make
  const std::vector<std::string> sealed_or_marked =
      SortedIds({RandomSealVectors(), DerivedSealVectors(), NotDerivedVectors()});

  // Then: every valid envelope is re-sealed unless the file says its nonce is not derived
  EXPECT_EQ(sealed_or_marked, opening);
  EXPECT_FALSE(NotDerivedVectors().empty());
}

}  // namespace

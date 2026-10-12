// SPDX-License-Identifier: PostgreSQL
// The deterministic nonce is 96 bits of a keyed hash. Over many distinct inputs it must not
// repeat: a repeat is a (key, nonce) pair used twice.
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>

#include <gtest/gtest.h>

#include "vectors.h"

namespace {

// The fewest plaintexts the test accepts (.agents/rules/testing.md).
constexpr size_t kFewest = 100000;

// 100,000 unless PG_GCM_COLLISION_N says more; CI sets 1,000,000 on a push and nightly.
// Anything that is not a whole decimal number reads as 0, which the test refuses: a gate
// that sealed one plaintext because of a typo ("1e6") has not passed.
size_t HowMany() {
  const char *text = std::getenv("PG_GCM_COLLISION_N");
  if (text == nullptr) return kFewest;
  const std::string digits(text);
  if (digits.empty() || digits.size() > 9 ||
      digits.find_first_not_of("0123456789") != std::string::npos) {
    return 0;
  }
  return static_cast<size_t>(std::stoul(digits));
}

// Seal `count` distinct plaintexts deterministically and return how many nonces repeat.
// Fixture code: the loop is here, not in the test body.
size_t RepeatedNonces(size_t count, const Bytes &key, const Bytes &aad) {
  std::mt19937_64 random(20261012);
  std::vector<Bytes> nonces;
  nonces.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    // Distinct by construction: a counter, then random bytes of a random length.
    Bytes plaintext(8 + random() % 24);
    for (size_t b = 0; b < 8; ++b) plaintext[b] = static_cast<uint8_t>(i >> (8 * b));
    for (size_t b = 8; b < plaintext.size(); ++b) plaintext[b] = static_cast<uint8_t>(random());
    Bytes envelope = EnvelopeBuffer(plaintext.size());
    if (gcm_seal(key.data(), key.size(), aad.data(), aad.size(), plaintext.data(),
                 plaintext.size(), 1, envelope.data(), envelope.size()) != GCM_OK) {
      return count;
    }
    nonces.emplace_back(envelope.begin() + 1, envelope.begin() + 1 + GCM_NONCE_LEN);
  }
  std::sort(nonces.begin(), nonces.end());
  return count - static_cast<size_t>(std::unique(nonces.begin(), nonces.end()) - nonces.begin());
}

TEST(DeterministicNonce, GivenManyDistinctPlaintexts_WhenSealedUnderOneKey_ThenNoNonceRepeats) {
  // Given
  const Vector &v = VectorNamed("det-256-korean");
  const size_t count = HowMany();
  ASSERT_GE(count, kFewest) << "PG_GCM_COLLISION_N must be a whole number of at least " << kFewest;

  // When
  const size_t repeated = RepeatedNonces(count, v.key, v.aad);
  std::cout << "[ counted  ] " << count << " plaintexts sealed, " << repeated << " repeated nonce(s)\n";

  // Then
  EXPECT_EQ(repeated, 0u);
}

TEST(DeterministicNonce, GivenOnePlaintextAndTwoAads_WhenSealed_ThenTheNoncesDiffer) {
  // Given: the same key and plaintext, with and without an AAD (spec 1.8, design O16)
  const Vector &plain = VectorNamed("det-256-korean");
  const Vector &bound = VectorNamed("det-256-aad");
  Bytes first = EnvelopeBuffer(plain.plaintext.size());
  Bytes second = EnvelopeBuffer(bound.plaintext.size());

  // When
  const gcm_error rc1 =
      gcm_seal(plain.key.data(), plain.key.size(), plain.aad.data(), plain.aad.size(),
               plain.plaintext.data(), plain.plaintext.size(), 1, first.data(), first.size());
  const gcm_error rc2 =
      gcm_seal(bound.key.data(), bound.key.size(), bound.aad.data(), bound.aad.size(),
               bound.plaintext.data(), bound.plaintext.size(), 1, second.data(), second.size());

  // Then: one (key, nonce) pair is never used for two different associated data
  EXPECT_EQ(rc1, GCM_OK);
  EXPECT_EQ(rc2, GCM_OK);
  EXPECT_EQ(plain.plaintext, bound.plaintext);
  EXPECT_NE(Bytes(first.begin() + 1, first.begin() + 13),
            Bytes(second.begin() + 1, second.begin() + 13));
}

}  // namespace

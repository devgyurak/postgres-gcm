// SPDX-License-Identifier: PostgreSQL
// spec/test-vectors.json as the suites will consume it (spec 1.11).
#include <gtest/gtest.h>

#include "vectors.h"

namespace {

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

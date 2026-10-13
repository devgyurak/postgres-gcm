// SPDX-License-Identifier: PostgreSQL
// The error-path resource test. With OpenSSL's allocator counted, each core call must give
// back every allocation it made — on success, on a forged tag, and when any one of its own
// allocations is refused (docs/design.md §4 step 6, §8 O8). Nothing can count inside a backend.
//
// What this does and does not execute: the paths an allocation failure or a tag mismatch
// reaches. An EVP call that fails for another reason after its context exists cannot be
// provoked from here; those exits are covered by structure — one `done:` label per function,
// which scripts/check-architecture.py enforces.
#include <cstdio>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include "alloc_counter.h"
#include "test_util.h"

namespace {

using ::testing::AnyOf;
using ::testing::Eq;

// More than any single core call allocates; AllocationBudget below fails if that stops being true.
constexpr int kSweep = 32;

enum class Op { kSealRandom, kSealDeterministic, kOpen };

const char *Name(Op op) {
  switch (op) {
    case Op::kSealRandom:
      return "SealRandom";
    case Op::kSealDeterministic:
      return "SealDeterministic";
    case Op::kOpen:
      return "Open";
  }
  return "Unknown";
}

// A key, a plaintext and its envelope, with buffers for one more operation.
struct Sealed {
  Bytes key = PatternKey();
  Bytes aad = Utf8("patients.name");
  Bytes plaintext = Utf8("홍길동");
  Bytes envelope = EnvelopeBuffer(plaintext.size());      // sealed with a random nonce
  Bytes det_envelope = EnvelopeBuffer(plaintext.size());  // what the deterministic variant gives
  Bytes scratch = EnvelopeBuffer(plaintext.size());       // output of a seal under test
  Bytes out = PlaintextBuffer(plaintext.size());          // output of an open under test
  Bytes out_untouched = out;
  size_t out_len = 0;

  Sealed() {
    (void)gcm_seal(key.data(), key.size(), aad.data(), aad.size(), plaintext.data(),
                   plaintext.size(), 0, envelope.data(), envelope.size());
    (void)gcm_seal(key.data(), key.size(), aad.data(), aad.size(), plaintext.data(),
                   plaintext.size(), 1, det_envelope.data(), det_envelope.size());
  }

  // The out buffer as a successful open leaves it: the plaintext, then the untouched spare byte.
  Bytes OutAfterSuccess() const {
    Bytes expected = out_untouched;
    std::copy(plaintext.begin(), plaintext.end(), expected.begin());
    return expected;
  }

  gcm_error Run(Op op) {
    switch (op) {
      case Op::kSealRandom:
        return gcm_seal(key.data(), key.size(), aad.data(), aad.size(), plaintext.data(),
                        plaintext.size(), 0, scratch.data(), scratch.size());
      case Op::kSealDeterministic:
        return gcm_seal(key.data(), key.size(), aad.data(), aad.size(), plaintext.data(),
                        plaintext.size(), 1, scratch.data(), scratch.size());
      case Op::kOpen:
        return gcm_open(key.data(), key.size(), aad.data(), aad.size(), envelope.data(),
                        envelope.size(), out.data(), out.size(), &out_len);
    }
    return GCM_BAD_LENGTH;
  }
};

// ---- The counter itself ----------------------------------------------------------------------

TEST(CountingAllocator, GivenInstalledFirstInMain_WhenItsResultIsRead_ThenOpenSslAcceptedIt) {
  // Given: main() installed the counter before any OpenSSL call

  // When
  const int result = alloc_counter::InstallResult();

  // Then: 0 would mean OpenSSL had already allocated and nothing below counts anything
  EXPECT_EQ(result, 1);
}

TEST(CountingAllocator, GivenInstalled_WhenOpenSslAllocates_ThenTheCounterMovesAndReturns) {
  // Given
  const long before = alloc_counter::Live();

  // When
  void *p = OPENSSL_malloc(16);
  const long during = alloc_counter::Live();
  OPENSSL_free(p);

  // Then
  EXPECT_EQ(during, before + 1);
  EXPECT_EQ(alloc_counter::Live(), before);
}

// ---- Each failing path, with the allocator working ---------------------------------------------

TEST(ErrorPath, GivenForgedTag_WhenOpened_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  s.envelope.back() ^= 0x01;
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kOpen);

  // Then
  EXPECT_EQ(rc, GCM_BAD_TAG);
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST(ErrorPath, GivenTruncatedEnvelope_WhenOpened_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  s.envelope.resize(28);
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kOpen);

  // Then
  EXPECT_EQ(rc, GCM_BAD_ENVELOPE);
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST(ErrorPath, GivenWrongKeyLength_WhenOpened_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  s.key.resize(31);
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kOpen);

  // Then
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
  EXPECT_EQ(alloc_counter::Live(), before);
}

// The two below leave before the core asks OpenSSL for anything; they are here so that every
// outcome of gcm_open has a case, and so that a later change which allocates first is seen.
TEST(ErrorPath, GivenKeyOfAnotherSuite_WhenOpened_ThenNoAllocationOutlivesTheCall) {
  // Given: a 16-byte key for an envelope sealed with AES-256
  Sealed s;
  s.key.resize(16);
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kOpen);

  // Then
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST(ErrorPath, GivenOutputBufferTooSmall_WhenOpened_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  s.out.resize(s.plaintext.size() - 1);
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kOpen);

  // Then
  EXPECT_EQ(rc, GCM_BAD_LENGTH);
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST(ErrorPath, GivenWrongKeyLength_WhenSealedDeterministic_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  s.key.resize(31);
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(Op::kSealDeterministic);

  // Then
  EXPECT_EQ(rc, GCM_BAD_KEY_LEN);
  EXPECT_EQ(alloc_counter::Live(), before);
}

// ---- Every operation, with the allocator working -----------------------------------------------

class EachOperation : public ::testing::TestWithParam<Op> {};

TEST_P(EachOperation, GivenWorkingAllocator_WhenRun_ThenNoAllocationOutlivesTheCall) {
  // Given
  Sealed s;
  const long before = alloc_counter::Live();

  // When
  const gcm_error rc = s.Run(GetParam());

  // Then
  EXPECT_EQ(rc, GCM_OK);
  EXPECT_EQ(alloc_counter::Live(), before);
}

// The sweep below covers every allocation only while a call makes fewer than kSweep of them.
TEST_P(EachOperation, GivenWorkingAllocator_WhenRun_ThenItAllocatesLessThanTheSweepCovers) {
  // Given
  Sealed s;
  const long before = alloc_counter::Total();

  // When
  (void)s.Run(GetParam());
  const long allocations = alloc_counter::Total() - before;

  // Then
  std::printf("[ counted  ] %s: %ld allocation(s) per call\n", Name(GetParam()), allocations);
  EXPECT_GT(allocations, 0);
  EXPECT_LT(allocations, kSweep);
}

// The injection reaches the core: with its very first allocation refused, the operation fails.
TEST_P(EachOperation, GivenFirstAllocationFails_WhenRun_ThenOpenSslFailure) {
  // Given
  Sealed s;
  alloc_counter::FailNth(1);

  // When
  const gcm_error rc = s.Run(GetParam());
  alloc_counter::FailNone();

  // Then
  EXPECT_EQ(rc, GCM_OPENSSL_FAILURE);
}

INSTANTIATE_TEST_SUITE_P(Core, EachOperation,
                         ::testing::Values(Op::kSealRandom, Op::kSealDeterministic, Op::kOpen),
                         [](const auto &info) { return std::string(Name(info.param)); });

// ---- Every allocation-failure path: refuse the n-th allocation inside the call ------------------

class AllocationFailure : public ::testing::TestWithParam<int> {};

TEST_P(AllocationFailure, GivenNthAllocationFails_WhenSealedRandom_ThenNothingLeaks) {
  // Given
  Sealed s;
  const long before = alloc_counter::Live();
  alloc_counter::FailNth(GetParam());

  // When
  const gcm_error rc = s.Run(Op::kSealRandom);
  alloc_counter::FailNone();

  // Then
  EXPECT_THAT(rc, AnyOf(GCM_OK, GCM_OPENSSL_FAILURE));
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST_P(AllocationFailure, GivenNthAllocationFails_WhenSealedDeterministic_ThenNothingLeaksAndNoWrongEnvelope) {
  // Given
  Sealed s;
  const long before = alloc_counter::Live();
  alloc_counter::FailNth(GetParam());

  // When
  const gcm_error rc = s.Run(Op::kSealDeterministic);
  alloc_counter::FailNone();

  // Then: the right envelope, or a cleansed buffer — never a silently different envelope
  EXPECT_THAT(rc, AnyOf(GCM_OK, GCM_OPENSSL_FAILURE));
  EXPECT_THAT(s.scratch, AnyOf(Eq(s.det_envelope), Eq(Bytes(s.scratch.size(), 0))));
  EXPECT_EQ(alloc_counter::Live(), before);
}

TEST_P(AllocationFailure, GivenNthAllocationFails_WhenOpened_ThenNothingLeaksAndNoWrongPlaintext) {
  // Given
  Sealed s;
  const long before = alloc_counter::Live();
  alloc_counter::FailNth(GetParam());

  // When
  const gcm_error rc = s.Run(Op::kOpen);
  alloc_counter::FailNone();

  // Then: an allocation failure is never reported as a tag mismatch, and the buffer holds
  // the plaintext or nothing at all
  EXPECT_THAT(rc, AnyOf(GCM_OK, GCM_OPENSSL_FAILURE));
  EXPECT_THAT(s.out, AnyOf(Eq(s.OutAfterSuccess()), Eq(Bytes(s.out.size(), 0))));
  EXPECT_EQ(alloc_counter::Live(), before);
}

INSTANTIATE_TEST_SUITE_P(FirstAllocations, AllocationFailure, ::testing::Range(1, kSweep + 1));

}  // namespace

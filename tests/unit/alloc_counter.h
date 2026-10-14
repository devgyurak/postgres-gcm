// SPDX-License-Identifier: PostgreSQL
// A counting allocator for OpenSSL (CRYPTO_set_mem_functions). It is the project's only leak
// gate: it cannot be installed inside a backend (docs/design.md §8, O8).
#ifndef PG_GCM_TESTS_ALLOC_COUNTER_H
#define PG_GCM_TESTS_ALLOC_COUNTER_H

namespace alloc_counter {

// Install before OpenSSL allocates anything. Returns what CRYPTO_set_mem_functions returned:
// 0 means OpenSSL had already allocated and nothing will be counted.
int Install();
int InstallResult();

long Live();   // allocations OpenSSL holds right now
long Total();  // allocations OpenSSL has asked for so far, failed ones included

// Make the n-th allocation from now return NULL (1 = the next one). FailNone() turns it off.
void FailNth(long n);
void FailNone();

}  // namespace alloc_counter

#endif  // PG_GCM_TESTS_ALLOC_COUNTER_H

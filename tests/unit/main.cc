// SPDX-License-Identifier: PostgreSQL
#include <cstdio>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "alloc_counter.h"

int main(int argc, char **argv) {
  // First, before any OpenSSL call: once OpenSSL has allocated, CRYPTO_set_mem_functions
  // returns 0 and the counter would count nothing.
  if (alloc_counter::Install() != 1) {
    std::fprintf(stderr, "CRYPTO_set_mem_functions did not return 1; nothing would be counted\n");
    return 2;
  }

  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}

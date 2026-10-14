// SPDX-License-Identifier: PostgreSQL
#include "alloc_counter.h"

#include <cstdlib>

#include <openssl/crypto.h>

namespace alloc_counter {
namespace {

long live = 0;
long total = 0;
long fail_at = 0;  // 0 = never
int install_result = -1;

bool ShouldFail() {
  ++total;
  return fail_at != 0 && --fail_at == 0;
}

void *CountingMalloc(size_t num, const char *, int) {
  if (ShouldFail()) return nullptr;
  void *p = std::malloc(num);
  if (p != nullptr) ++live;
  return p;
}

void CountingFree(void *addr, const char *, int) {
  if (addr == nullptr) return;
  --live;
  std::free(addr);
}

// OpenSSL hands a custom realloc every case, a null pointer and a zero size included.
void *CountingRealloc(void *addr, size_t num, const char *file, int line) {
  if (addr == nullptr) return CountingMalloc(num, file, line);
  if (num == 0) {
    CountingFree(addr, file, line);
    return nullptr;
  }
  if (ShouldFail()) return nullptr;
  return std::realloc(addr, num);
}

}  // namespace

int Install() {
  install_result = CRYPTO_set_mem_functions(CountingMalloc, CountingRealloc, CountingFree);
  return install_result;
}

int InstallResult() { return install_result; }
long Live() { return live; }
long Total() { return total; }
void FailNth(long n) { fail_at = n; }
void FailNone() { fail_at = 0; }

}  // namespace alloc_counter

// SPDX-License-Identifier: PostgreSQL
#ifndef PG_GCM_TESTS_TEST_UTIL_H
#define PG_GCM_TESTS_TEST_UTIL_H

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

extern "C" {
#include "gcm.h"
}

using Bytes = std::vector<uint8_t>;

// Hex text to bytes. Fixture code, not a test body. Text that is not whole bytes of
// hexadecimal ends the run: a fixture that quietly read something else would prove nothing.
inline Bytes Hex(const std::string &hex) {
  if (hex.size() % 2 != 0 || hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
    std::cerr << "not hexadecimal bytes: " << hex << "\n";
    std::exit(2);
  }
  Bytes out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

inline Bytes Utf8(const std::string &text) { return Bytes(text.begin(), text.end()); }

// The public 00..1f pattern key (.agents/rules/testing.md). Never a real key.
inline Bytes PatternKey() {
  return Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

// The all-zero key of the GCM specification's test cases: the other public key a test may use.
inline Bytes ZeroKey() { return Bytes(32, 0x00); }

// The pattern key cut or zero-padded to n bytes, with one spare byte so data() is never null.
inline Bytes KeyOfLength(size_t n) {
  Bytes key = PatternKey();
  key.resize(n + 1, 0x00);
  return key;
}

// A buffer of exactly the envelope's size for a plaintext of n bytes.
inline Bytes EnvelopeBuffer(size_t n) { return Bytes(n + GCM_ENVELOPE_OVERHEAD); }

// A plaintext buffer that is never empty, so data() is never null.
inline Bytes PlaintextBuffer(size_t n) { return Bytes(n + 1, 0xAA); }

#endif  // PG_GCM_TESTS_TEST_UTIL_H

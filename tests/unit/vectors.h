// SPDX-License-Identifier: PostgreSQL
// spec/test-vectors.json, read once. Every known answer the suite uses comes from here.
#ifndef PG_GCM_TESTS_VECTORS_H
#define PG_GCM_TESTS_VECTORS_H

#include <initializer_list>
#include <iosfwd>
#include <string>
#include <vector>

#include "test_util.h"

struct Vector {
  std::string id;
  std::string kind;    // nist | random | det
  std::string expect;  // ok | bad_tag | bad_envelope | bad_key_length
  bool nonce_derived = true;  // false: a det vector no sealer can reproduce
  Bytes key, nonce, aad, plaintext;
  Bytes envelope;         // envelope vectors
  Bytes ciphertext, tag;  // nist vectors
};

// gtest prints a parameter when a test fails; the id is what a reader needs.
std::ostream &operator<<(std::ostream &os, const Vector &v);

// Every vector of the file, in file order.
const std::vector<Vector> &AllVectors();

// The vectors a suite is parameterised over. Selection is fixture code, not a test body.
std::vector<Vector> NistVectors();
std::vector<Vector> OpeningVectors();        // envelopes that open
std::vector<Vector> RandomSealVectors();     // ok, random: re-sealed with their nonce
std::vector<Vector> DerivedSealVectors();    // ok, det, nonce derived: re-sealed from inputs
std::vector<Vector> FailingVectors();        // envelopes that do not open
std::vector<Vector> NotDerivedVectors();     // ok, det, nonce not derived: no sealer makes them

// The ids of several groups together, sorted; a vector in two groups appears twice.
std::vector<std::string> SortedIds(std::initializer_list<std::vector<Vector>> groups);

// One vector by id; fails the test run if the file does not have it.
const Vector &VectorNamed(const char *id);

// The core's error for a vector's `expect`.
gcm_error ExpectedError(const Vector &v);

#endif  // PG_GCM_TESTS_VECTORS_H

// SPDX-License-Identifier: PostgreSQL
#include "vectors.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <ostream>

#include <nlohmann/json.hpp>

namespace {

[[noreturn]] void Refuse(const std::string &id, const std::string &why) {
  std::cerr << "spec/test-vectors.json, vector " << id << ": " << why << "\n";
  std::exit(2);
}

// A member the vector's kind must carry. A misspelt name must not read as an empty value:
// aad-different without its aad would still fail to open, for the wrong reason.
Bytes Member(const nlohmann::json &v, const std::string &id, const char *name) {
  if (!v.contains(name)) Refuse(id, std::string("no member ") + name);
  return Hex(v.at(name).get<std::string>());
}

std::vector<Vector> Load() {
  std::ifstream file(PG_GCM_VECTORS);
  if (!file) {
    std::cerr << "cannot open " << PG_GCM_VECTORS << "\n";
    std::exit(2);
  }
  const nlohmann::json document = nlohmann::json::parse(file);
  std::vector<Vector> vectors;
  for (const auto &v : document.at("vectors")) {
    Vector out;
    out.id = v.at("id").get<std::string>();
    out.kind = v.at("kind").get<std::string>();
    out.expect = v.at("expect").get<std::string>();
    out.nonce_derived = v.value("nonce_derived", true);
    if (out.kind != "nist" && out.kind != "random" && out.kind != "det") {
      Refuse(out.id, "unknown kind " + out.kind);
    }
    ExpectedError(out);  // ends the run on an unknown expect
    out.key = Member(v, out.id, "key_hex");
    out.aad = Member(v, out.id, "aad_hex");
    if (out.kind == "nist") {
      out.ciphertext = Member(v, out.id, "ciphertext_hex");
      out.tag = Member(v, out.id, "tag_hex");
    } else {
      out.envelope = Member(v, out.id, "envelope_hex");
    }
    // A failing vector is an envelope and what to open it with; it has no plaintext.
    if (out.expect == "ok") {
      out.nonce = Member(v, out.id, "nonce_hex");
      out.plaintext = Member(v, out.id, "plaintext_hex");
    }
    vectors.push_back(out);
  }
  return vectors;
}

template <typename Predicate>
std::vector<Vector> Select(Predicate wanted) {
  std::vector<Vector> out;
  for (const Vector &v : AllVectors()) {
    if (wanted(v)) out.push_back(v);
  }
  return out;
}

bool IsEnvelope(const Vector &v) { return v.kind != "nist"; }

}  // namespace

std::ostream &operator<<(std::ostream &os, const Vector &v) { return os << v.id; }

std::string VectorName(const ::testing::TestParamInfo<Vector> &info) {
  std::string name = info.param.id;
  std::replace(name.begin(), name.end(), '-', '_');
  return name;
}

const std::vector<Vector> &AllVectors() {
  static const std::vector<Vector> vectors = Load();
  return vectors;
}

std::vector<Vector> NistVectors() {
  return Select([](const Vector &v) { return v.kind == "nist"; });
}

std::vector<Vector> OpeningVectors() {
  return Select([](const Vector &v) { return IsEnvelope(v) && v.expect == "ok"; });
}

std::vector<Vector> RandomSealVectors() {
  return Select([](const Vector &v) { return v.kind == "random" && v.expect == "ok"; });
}

std::vector<Vector> DerivedSealVectors() {
  return Select(
      [](const Vector &v) { return v.kind == "det" && v.expect == "ok" && v.nonce_derived; });
}

std::vector<Vector> FailingVectors() {
  return Select([](const Vector &v) { return IsEnvelope(v) && v.expect != "ok"; });
}

std::vector<Vector> NotDerivedVectors() {
  return Select([](const Vector &v) { return IsEnvelope(v) && v.expect == "ok" && !v.nonce_derived; });
}

std::vector<std::string> SortedIds(std::initializer_list<std::vector<Vector>> groups) {
  std::vector<std::string> ids;
  for (const auto &group : groups) {
    for (const Vector &v : group) ids.push_back(v.id);
  }
  std::sort(ids.begin(), ids.end());
  return ids;
}

const Vector &VectorNamed(const char *id) {
  for (const Vector &v : AllVectors()) {
    if (v.id == id) return v;
  }
  std::cerr << "spec/test-vectors.json has no vector " << id << "\n";
  std::exit(2);
}

gcm_error ExpectedError(const Vector &v) {
  if (v.expect == "ok") return GCM_OK;
  if (v.expect == "bad_tag") return GCM_BAD_TAG;
  if (v.expect == "bad_envelope") return GCM_BAD_ENVELOPE;
  if (v.expect == "bad_key_length") return GCM_BAD_KEY_LEN;
  std::cerr << "unknown expect " << v.expect << " in " << v.id << "\n";
  std::exit(2);
}

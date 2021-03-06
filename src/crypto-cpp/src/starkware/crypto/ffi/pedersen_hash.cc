#include "starkware/crypto/ffi/pedersen_hash.h"
#include "starkware/crypto/pedersen_hash.h"

#include <array>

#include "starkware/algebra/prime_field_element.h"
#include "starkware/crypto/ffi/utils.h"

#include "third_party/gsl/gsl-lite.hpp"

namespace starkware {

namespace {

using ValueType = PrimeFieldElement::ValueType;

constexpr size_t kElementSize = sizeof(ValueType);
constexpr size_t kOutBufferSize = 1024;
static_assert(kOutBufferSize >= kElementSize, "kOutBufferSize is not big enough");

}  // namespace

extern "C" int Hash(
    const gsl::byte in1[kElementSize], const gsl::byte in2[kElementSize],
    gsl::byte out[kOutBufferSize]) {
  try {
    auto hash = PedersenHash(
        PrimeFieldElement::FromBigInt(Deserialize(gsl::make_span(in1, kElementSize))),
        PrimeFieldElement::FromBigInt(Deserialize(gsl::make_span(in2, kElementSize))));
    Serialize(hash.ToStandardForm(), gsl::make_span(out, kElementSize));
  } catch (const std::exception& e) {
    return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
  } catch (...) {
    return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
  }
  return 0;
}

}  // namespace starkware

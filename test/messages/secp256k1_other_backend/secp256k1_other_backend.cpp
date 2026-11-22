// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1 refuses a backend other than libsecp256k1 where it is instantiated, with the
// family's generated refusal, which names the backends that have it (design D33).

// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1.hpp:* {{webcpp::crypto: bearssl has no secp256k1. The backends that have it: secp256k1 (native, wasip2, wasip3, emscripten).}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 33> const key{};
    auto const parsed =
        webcpp::crypto::curves::secp256k1::public_key::make<webcpp::crypto::backends::bearssl>(key);
    return parsed ? 0 : 1;
}

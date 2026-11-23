// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 key pair named with libsodium, which has no P-256, stops where it is made, with the
// capability table's refusal, which names the backends that have it.

// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: sodium has no P-256. The backends that have it: bearssl (native, wasip2, wasip3, emscripten).}}
// clang-format on

#include <webcpp/crypto/curves/p256.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    return webcpp::crypto::curves::p256::basic_keypair<
               webcpp::crypto::backends::sodium>::from_secret(scalar)
               ? 0
               : 1;
}

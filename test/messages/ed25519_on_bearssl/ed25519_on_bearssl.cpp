// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair named with BearSSL, which has no Ed25519, stops where it is made, with the
// capability table's refusal, which names the backends that have it.

// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: bearssl has no Ed25519. The backends that have it: sodium (native, wasip2, wasip3, emscripten).}}
// clang-format on

#include <webcpp/crypto/curves/ed25519.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const seed{};
    return webcpp::crypto::curves::ed25519::basic_keypair<webcpp::crypto::backends::bearssl>::make(
               seed)
               ? 0
               : 1;
}

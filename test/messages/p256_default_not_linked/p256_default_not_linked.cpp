// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that makes a P-256 key pair on its default backend, BearSSL on every target, and
// does not link it stops where it makes it, with the line that links it.

// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: P-256's default backend on this target is BearSSL, which is not linked, and the one backend that has it there. Add /webcpp/crypto//p256-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//p256-default ; (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on

#include <webcpp/crypto/curves/p256.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    return webcpp::crypto::curves::p256::keypair::from_secret(scalar) ? 0 : 1;
}

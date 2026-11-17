// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that makes an Ed25519 key pair on its default backend, libsodium on every target
// (design D32), and does not link it stops where it makes it, with the line that links it.

// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: Ed25519's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /third_party//sodium to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//sodium ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// clang-format on

#include <webcpp/crypto/curves/ed25519.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const seed{};
    return webcpp::crypto::curves::ed25519::keypair::make(seed) ? 0 : 1;
}

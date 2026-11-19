// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that agrees an X25519 shared secret on its default backend, libsodium on every target,
// without linking it, stops where it calls it, with the line that links libsodium, the one backend
// that has it (design D32).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/x25519.hpp:* {{webcpp::crypto: X25519's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//x25519-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//x25519-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// clang-format on

#include <webcpp/crypto/curves/x25519.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::curves::x25519::agree(key, key) ? 0 : 1;
}

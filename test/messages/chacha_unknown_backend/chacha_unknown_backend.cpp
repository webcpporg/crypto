// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names a type of its own as ChaCha20-Poly1305's backend stops where it makes the
// AEAD, with the backends that have the family.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/ciphers/aead.hpp:* {{webcpp::crypto: ChaCha20-Poly1305 has no backend of that name. The backends that have it: sodium (native, wasip2, wasip3, emscripten), bearssl (native, wasip2, wasip3, emscripten), openssl (native, wasip2, wasip3).}}
// clang-format on

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

namespace {

/** A type of the program's own, which is no backend. */
struct my_backend {};

}  // namespace

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::ciphers::chacha20_poly1305<my_backend>::from_key(key) ? 0 : 1;
}

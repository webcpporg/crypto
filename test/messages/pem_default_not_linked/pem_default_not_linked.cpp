// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that armours DER as PEM on its default backend, libsodium on every target, without
// linking it, stops where it calls it, with the line that links libsodium, the one backend that has
// it (design D32).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/pem.hpp:* {{webcpp::crypto: PEM's default backend on this target is libsodium, which is not linked, and the one backend that has it there. Add /webcpp/crypto//pem-default, the default's library on every target, to the program's Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//pem-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link libsodium built with webcpp's src/canary_sodium.c)}}
// clang-format on

#include <webcpp/crypto/pem.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 1> const der{};
    std::array<char, 128> out{};
    return webcpp::crypto::pem::armour("A", der, out) ? 0 : 1;
}

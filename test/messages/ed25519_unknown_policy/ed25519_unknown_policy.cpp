// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names a policy of its own in Ed25519's verify, on its default backend linked,
// stops where it calls it, with the one policy there is.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: Ed25519's only verification policy is curves::ed25519::strict.}}
// clang-format on

#include <webcpp/crypto/curves/ed25519.hpp>

#include <array>
#include <cstdint>

namespace {

/** A verification policy of the program's own. */
struct lenient {};

}  // namespace

int main() {
    std::array<std::uint8_t, 32> const public_key{};
    std::array<std::uint8_t, 64> const signature{};
    return webcpp::crypto::curves::ed25519::verify<lenient>(public_key, {}, signature) ? 0 : 1;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A digest marked through a span of a dynamic size stops at the marker, with the fixed-size
// digest to give instead, and with that error alone, while the marker of a fixed-size span
// compiles: no call reads a span's run-time size to tell a digest from a message.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::prehashed takes a digest of a fixed size: a std::array<std::uint8_t, N> or a std::span<std::uint8_t const, N>.}}
// clang-format on
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>
#include <span>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const bytes{};
    // The marker of a fixed-size span compiles.
    crypto::prehashed const fixed{std::span<std::uint8_t const, 32>(bytes)};
    crypto::prehashed const dynamic{std::span<std::uint8_t const>(bytes)};
    return static_cast<int>(fixed.digest.size() + dynamic.digest.size());
}

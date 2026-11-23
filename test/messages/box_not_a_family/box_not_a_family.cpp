// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hybrid::basic_box given a type that is no box family's, and no backend, stops with the
// families it takes, and with that error alone: the default backend is read for a box family in
// the type's place, so a type that has no default of its own adds no error before it.

// clang-format off
// expected-error@webcpp/crypto/hybrid/box.hpp:* {{webcpp::crypto: hybrid::basic_box takes a box family: families::box_xsalsa20poly1305 or families::box_xchacha20poly1305.}}
// clang-format on
#include <webcpp/crypto/hybrid/box.hpp>

#include <array>
#include <cstdint>

namespace {

/** A type that names no family, and so has no default backend. */
struct not_a_family {};

}  // namespace

int main() {
    std::array<std::uint8_t, 32> const key{};
    return webcpp::crypto::hybrid::basic_box<not_a_family>::from_keys(key, key) ? 0 : 1;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time comparison is constant_time_equal, a name that says what it guarantees, with
// no alias left at the old name (design D10), now webcpp::secure's: a program that still calls
// crypto::equal stops at the call, with that error alone, although a crypto header is included.

#include <webcpp/crypto/error.hpp>

#include <array>
#include <cstdint>
#include <span>

int main() {
    std::array<std::uint8_t, 4> const first{1, 2, 3, 4};
    std::array<std::uint8_t, 4> const second{1, 2, 3, 4};
    // expected-error@+1 {{no member named 'equal' in namespace 'webcpp::crypto'}}
    bool const same = webcpp::crypto::equal(std::span<std::uint8_t const>(first),
                                            std::span<std::uint8_t const>(second));
    return same ? 0 : 1;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time comparison is webcpp::secure's constant_time_equal, with no alias left in
// crypto: a program that still calls crypto::constant_time_equal stops at the call, with that
// error alone, although crypto's convenience header is included.

#include <webcpp/crypto.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 4> const first{1, 2, 3, 4};
    std::array<std::uint8_t, 4> const second{1, 2, 3, 4};
    // expected-error@+1 {{no member named 'constant_time_equal' in namespace 'webcpp::crypto'}}
    bool const same = webcpp::crypto::constant_time_equal(first, second);
    return same ? 0 : 1;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The erasure of a buffer the program owns is webcpp::secure's erase_secret, with no alias left in
// crypto: a program that still calls crypto::erase_secret stops at the call, with that error
// alone, although crypto's convenience header is included.

#include <webcpp/crypto.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 4> password_bytes{1, 2, 3, 4};
    // A statement that starts with an unknown qualified name reads as a declaration: clang says
    // "type", as a program that still calls it sees it.
    // expected-error@+1 {{no type named 'erase_secret' in namespace 'webcpp::crypto'}}
    webcpp::crypto::erase_secret(password_bytes);
    return password_bytes[0];
}

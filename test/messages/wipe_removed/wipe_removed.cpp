// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The erasure of a buffer the program owns is erase_secret, a name that says what it is for, with
// no alias left at the old name (design D10): a program that still calls crypto::wipe stops at
// the call, with that error alone, although the new header is included.

#include <webcpp/crypto/erase_secret.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 4> password_bytes{1, 2, 3, 4};
    // A statement that starts with an unknown qualified name reads as a declaration: clang says
    // "type", as a program that still calls it sees it.
    // expected-error@+1 {{no type named 'wipe' in namespace 'webcpp::crypto'}}
    webcpp::crypto::wipe(password_bytes);
    return password_bytes[0];
}

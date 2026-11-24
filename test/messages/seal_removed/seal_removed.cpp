// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free AEAD forms are secret_key_encryption::aead's, with no alias left in crypto:: (design
// D11): a program that still names crypto::seal or crypto::open stops at each, with those two
// errors alone, although the cipher's header, which brings the new forms, is included. The names
// are declared, not called: on WASI clang corrects open to the C library's fopen in its message,
// and a call of the corrected function would add an error of its own.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

// expected-error@+1 {{no member named 'seal' in namespace 'webcpp::crypto'}}
using webcpp::crypto::seal;
// expected-error@+1 {{no member named 'open' in namespace 'webcpp::crypto'}}
using webcpp::crypto::open;

int main() {
    return 0;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that uses libsecp256k1's backend without linking /third_party//secp256k1 stops
// with the instruction to add it (spec section 4.3, the sixth row).

// expected-error@webcpp/crypto/backends/secp256k1.hpp:* {{webcpp::crypto:
// <webcpp/crypto/secp256k1.hpp> needs libsecp256k1, which is not linked. In the program's Jamfile,
// add /third_party//secp256k1 beside /webcpp/crypto//crypto. (without b2: define
// WEBCPP_CRYPTO_HAS_SECP256K1=1 and link libsecp256k1 built with webcpp's src/canary_secp256k1.c)}}
#include <webcpp/crypto/backends/secp256k1.hpp>

int main() {
    return 0;
}

// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that uses libsecp256k1's backend without linking /third_party//secp256k1 stops at
// backends/secp256k1.hpp's instruction to add it (spec section 4.3): on MSVC the compile fails.
// The text is checked on clang, in test/messages/secp256k1_not_linked.
#include <webcpp/crypto/backends/secp256k1.hpp>

int main() {
    return 0;
}

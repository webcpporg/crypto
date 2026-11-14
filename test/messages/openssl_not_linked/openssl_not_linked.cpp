// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that selects OpenSSL and does not link it stops with the instruction to add
// /webcpp/crypto//openssl (spec section 4.3).

// clang-format off
// expected-error@webcpp/crypto/backends/openssl.hpp:* {{webcpp::crypto: the backend OpenSSL is used and not linked. In the program's Jamfile, add /webcpp/crypto//openssl beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)}}
// clang-format on
#include <webcpp/crypto/backends/openssl.hpp>

int main() {
    return 0;
}

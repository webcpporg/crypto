// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that sets the memory option of the OpenSSL backend and does not link OpenSSL
// stops with the instruction to add /webcpp/crypto//openssl (spec section 3.7).

// clang-format off
// expected-error@webcpp/crypto/config.hpp:* {{webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE routes OpenSSL's allocations, and OpenSSL is not linked. In the program's Jamfile, add /webcpp/crypto//openssl beside /webcpp/crypto//crypto, or remove that define. (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)}}
// clang-format on
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}

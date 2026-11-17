// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names BearSSL in the type and does not link it stops at the backend's header
// with the instruction to add it (spec section 4.3).

// clang-format off
// expected-error@webcpp/crypto/backends/bearssl.hpp:* {{webcpp::crypto: the backend BearSSL is used and not linked. In the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

webcpp::crypto::ciphers::gcm<webcpp::crypto::ciphers::aes256<webcpp::crypto::backends::bearssl>>*
    unused = nullptr;

int main() {
    return 0;
}

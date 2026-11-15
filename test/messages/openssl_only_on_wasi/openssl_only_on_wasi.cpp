// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that links OpenSSL alone and uses BearSSL, WebAssembly's
// default, stops with the instruction to add BearSSL or to select OpenSSL with its define
// (spec section 4.3).

// clang-format off
// expected-error@webcpp/crypto/backends/bearssl.hpp:* {{webcpp::crypto: the backend BearSSL is used and not linked. In the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, or, with /webcpp/crypto//openssl linked, select OpenSSL with <define>WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL. (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>

int main() {
    return 0;
}

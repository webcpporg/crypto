// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that links no backend and uses the default's header stops with the
// instruction to add OpenSSL or BearSSL (spec section 4.3, the second row).

// clang-format off
// expected-error@webcpp/crypto/backends/bearssl.hpp:* {{webcpp::crypto: no backend is linked. In the program's Jamfile, add /webcpp/crypto//openssl (OpenSSL built from source) or /third_party//bearssl (built from source) beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//openssl ; (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto, or define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>

int main() {
    return 0;
}

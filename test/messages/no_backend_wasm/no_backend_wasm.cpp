// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for WebAssembly that links no backend and uses the default's header stops
// with the instruction to add BearSSL (spec section 4.3, the first row).

// clang-format off
// expected-error@webcpp/crypto/backends/bearssl.hpp:* {{webcpp::crypto: no backend is linked. On WebAssembly the backend is BearSSL: in the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//bearssl ; (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)}}
// clang-format on
#include <webcpp/crypto/backends/bearssl.hpp>

int main() {
    return 0;
}

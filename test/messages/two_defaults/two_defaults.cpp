// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that selects both default backends stops with the instruction to keep one
// (spec section 4.3, the ninth row).

// clang-format off
// expected-error@webcpp/crypto/config.hpp:* {{webcpp::crypto: both WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL and WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL are defined. Keep one.}}
// clang-format on
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}

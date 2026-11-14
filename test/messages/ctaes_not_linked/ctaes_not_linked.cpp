// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names ctaes and does not link it stops with the instruction to add
// /third_party//ctaes (spec section 4.3, the fifth row).

// clang-format off
// expected-error@webcpp/crypto/backends/ctaes.hpp:* {{webcpp::crypto: the backend ctaes is used and not linked. In the program's Jamfile, add /third_party//ctaes beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_CTAES=1 and link ctaes.c with webcpp's src/canary_ctaes.c)}}
// clang-format on
#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>

webcpp::crypto::aes256<webcpp::crypto::backends::ctaes>* unused = nullptr;

int main() {
    return 0;
}

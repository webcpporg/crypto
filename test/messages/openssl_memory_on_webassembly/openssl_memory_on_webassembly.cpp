// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that sets the memory option of the OpenSSL backend stops with
// the instruction to remove the define: the option is native (spec section 3.7).

// clang-format off
// expected-error@webcpp/crypto/config.hpp:* {{webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE is an option of native programs, and this program is built for WebAssembly. Remove that define from the program's Jamfile.}}
// clang-format on
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}
